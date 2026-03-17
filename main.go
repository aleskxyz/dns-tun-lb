package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// backendPool is a named set of backends for one domain suffix.
type backendPool struct {
	protocol     string
	name         string
	domainSuffix string
	backends     []BackendConfig
	ring         *hashRing
}

type server struct {
	cfg             *Config
	conn            net.PacketConn
	pools           []backendPool
	forwardAddr     *net.UDPAddr
	sessionTracker  *sessionTracker
}

func newServer(cfg *Config) (*server, error) {
	if strings.TrimSpace(cfg.Global.ListenAddress) == "" {
		return nil, fmt.Errorf("global.listen_address is required and cannot be empty")
	}
	conn, err := net.ListenPacket("udp", cfg.Global.ListenAddress)
	if err != nil {
		return nil, err
	}

	var forwardAddr *net.UDPAddr
	if cfg.Global.DefaultDNSBehavior.Mode == DefaultDNSModeForward {
		if cfg.Global.DefaultDNSBehavior.ForwardResolver == "" {
			conn.Close()
			return nil, fmt.Errorf("default_dns_behavior.mode is 'forward' but forward_resolver is empty")
		}
		forwardAddr, err = net.ResolveUDPAddr("udp", cfg.Global.DefaultDNSBehavior.ForwardResolver)
		if err != nil {
			conn.Close()
			return nil, err
		}
	}

	var pools []backendPool
	seenSuffix := make(map[string]string)
	for _, p := range cfg.Protocols.Dnstt.Pools {
		if strings.TrimSpace(p.DomainSuffix) == "" {
			conn.Close()
			return nil, fmt.Errorf("dnstt pool %q has empty domain_suffix", p.Name)
		}
		if len(p.Backends) == 0 {
			continue
		}
		suffixKey := strings.ToLower(strings.TrimSpace(p.DomainSuffix))
		if prev := seenSuffix[suffixKey]; prev != "" {
			conn.Close()
			return nil, fmt.Errorf("duplicate domain_suffix %q: already used by %s (dnstt pool %q)", p.DomainSuffix, prev, p.Name)
		}
		seenSuffix[suffixKey] = "dnstt pool " + p.Name
		ring := newHashRing(p.Backends, 0)
		pools = append(pools, backendPool{
			protocol:     "dnstt",
			name:         p.Name,
			domainSuffix: suffixKey,
			backends:     p.Backends,
			ring:         ring,
		})
	}
	for _, p := range cfg.Protocols.Slipstream.Pools {
		if strings.TrimSpace(p.DomainSuffix) == "" {
			conn.Close()
			return nil, fmt.Errorf("slipstream pool %q has empty domain_suffix", p.Name)
		}
		if len(p.Backends) == 0 {
			continue
		}
		seenLbID := make(map[uint8]string)
		for _, b := range p.Backends {
			if b.LbID == nil {
				conn.Close()
				return nil, fmt.Errorf("slipstream pool %q backend %q missing required lb_id", p.Name, b.ID)
			}
			if prev := seenLbID[*b.LbID]; prev != "" {
				conn.Close()
				return nil, fmt.Errorf("slipstream pool %q duplicate lb_id %d (backends %q and %q)", p.Name, *b.LbID, prev, b.ID)
			}
			seenLbID[*b.LbID] = b.ID
		}
		suffixKey := strings.ToLower(strings.TrimSpace(p.DomainSuffix))
		if prev := seenSuffix[suffixKey]; prev != "" {
			conn.Close()
			return nil, fmt.Errorf("duplicate domain_suffix %q: already used by %s (slipstream pool %q)", p.DomainSuffix, prev, p.Name)
		}
		seenSuffix[suffixKey] = "slipstream pool " + p.Name
		ring := newHashRing(p.Backends, 0)
		pools = append(pools, backendPool{
			protocol:     "slipstream",
			name:         p.Name,
			domainSuffix: suffixKey,
			backends:     p.Backends,
			ring:         ring,
		})
	}

	return &server{
		cfg:             cfg,
		conn:            conn,
		pools:           pools,
		forwardAddr:     forwardAddr,
		sessionTracker:  newSessionTracker(10 * time.Minute),
	}, nil
}

func (s *server) serve() error {
	defer s.conn.Close()
	buf := make([]byte, 4096)
	for {
		n, addr, err := s.conn.ReadFrom(buf)
		if err != nil {
			return err
		}
		frontendPacketsIn.Inc()
		frontendBytesIn.Add(float64(n))
		packet := make([]byte, n)
		copy(packet, buf[:n])
		go s.handlePacket(packet, addr)
	}
}

// longestMatchingPool returns the pool with the longest matching domain suffix, or nil.
func longestMatchingPool(qname string, pools []backendPool) *backendPool {
	var best *backendPool
	for i := range pools {
		p := &pools[i]
		if !MatchDomainSuffix(qname, p.domainSuffix) {
			continue
		}
		if best == nil || len(p.domainSuffix) > len(best.domainSuffix) {
			best = p
		}
	}
	return best
}

func (s *server) handlePacket(packet []byte, src net.Addr) {
	var msg dns.Msg
	if err := msg.Unpack(packet); err != nil {
		parseErrorsTotal.WithLabelValues("dns_unpack").Inc()
		dnsRequestsTotal.WithLabelValues("other").Inc()
		s.forwardOrDrop(packet, src)
		return
	}

	// Route by configured domain suffix only (longest match).
	if len(msg.Question) == 1 {
		q := msg.Question[0]
		pool := longestMatchingPool(q.Name, s.pools)
		if pool != nil {
			var sid []byte
			var haveSession bool

			if q.Qtype != dns.TypeTXT {
				unsupportedQueriesTotal.WithLabelValues(fmt.Sprintf("%d", q.Qtype)).Inc()
			} else {
				switch pool.protocol {
				case "dnstt":
					sid, haveSession = extractDNSTTSessionID(&msg, pool.domainSuffix)
				case "slipstream":
					sid, haveSession = extractSlipstreamSessionID(&msg, pool.domainSuffix)
				default:
					haveSession = false
				}
				if !haveSession {
					rejectedRequestsTotal.WithLabelValues("no_session_id").Inc()
				}
			}

			var backend BackendConfig
			if pool.protocol == "slipstream" && len(sid) > 0 {
				serverID, decodeOK := decodeSlipstreamQUICLBServerID(&msg, pool.domainSuffix)
				if decodeOK {
					for i := range pool.backends {
						b := &pool.backends[i]
						if *b.LbID == serverID {
							backend = *b
							break
						}
					}
				}
			}
			if backend.ID == "" && backend.Address == "" {
				backend = pool.ring.choose(pool.protocol, pool.domainSuffix, sid)
			}

			if s.sessionTracker != nil {
				s.sessionTracker.observeSession(pool.protocol, pool.name, pool.domainSuffix, backend, sid)
			}
			dnsRequestsTotal.WithLabelValues(pool.protocol).Inc()
			dnsRoutedRequestsTotal.WithLabelValues(pool.protocol, pool.name).Inc()
			labels := labelsForBackend(pool.protocol, pool.name, pool.domainSuffix, backend)
			backendRequestsTotal.With(labels).Inc()
			if q.Qtype == dns.TypeTXT && len(sid) > 0 {
				logDebugf("%s session %x -> backend %s (%s)", pool.protocol, sid, backend.ID, backend.Address)
			} else {
				logDebugf("%s qtype=%d name=%s -> backend %s (%s)", pool.protocol, q.Qtype, q.Name, backend.ID, backend.Address)
			}
			s.forwardToBackend(packet, src, pool.protocol, pool.name, pool.domainSuffix, backend)
			return
		}
	}

	dnsRequestsTotal.WithLabelValues("other").Inc()
	s.forwardOrDrop(packet, src)
}

func (s *server) forwardOrDrop(packet []byte, src net.Addr) {
	if s.forwardAddr == nil {
		dnsDroppedRequestsTotal.WithLabelValues("no_forwarder").Inc()
		return
	}
	// Forward to default resolver and send response back to client.
	resolverConn, err := net.DialUDP("udp", nil, s.forwardAddr)
	if err != nil {
		logErrorf("forward dial: %v", err)
		dnsDroppedRequestsTotal.WithLabelValues("forward_dial_error").Inc()
		return
	}
	defer resolverConn.Close()

	dnsForwardedRequestsTotal.Inc()

	deadline := time.Now().Add(s.cfg.parsedReadTimeout)
	resolverConn.SetWriteDeadline(deadline)
	resolverConn.SetReadDeadline(deadline)

	if _, err := resolverConn.Write(packet); err != nil {
		logErrorf("forward write: %v", err)
		dnsDroppedRequestsTotal.WithLabelValues("forward_write_error").Inc()
		return
	}
	resp := make([]byte, 4096)
	n, _, err := resolverConn.ReadFrom(resp)
	if err != nil {
		logErrorf("forward read: %v", err)
		dnsDroppedRequestsTotal.WithLabelValues("forward_read_error").Inc()
		return
	}
	if _, err := s.conn.WriteTo(resp[:n], src); err != nil {
		logErrorf("forward reply: %v", err)
		dnsDroppedRequestsTotal.WithLabelValues("forward_reply_error").Inc()
		return
	}
	frontendPacketsOut.Inc()
	frontendBytesOut.Add(float64(n))
}

func (s *server) forwardToBackend(packet []byte, src net.Addr, protocol, pool, domain string, backend BackendConfig) {
	udpAddr, err := net.ResolveUDPAddr("udp", backend.Address)
	if err != nil {
		logErrorf("resolve backend: %v", err)
		backendErrorsTotal.With(labelsForBackendWithStage(protocol, pool, domain, backend, "resolve")).Inc()
		return
	}
	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		logErrorf("dial backend: %v", err)
		backendErrorsTotal.With(labelsForBackendWithStage(protocol, pool, domain, backend, "dial")).Inc()
		return
	}
	defer conn.Close()

	deadline := time.Now().Add(s.cfg.parsedReadTimeout)
	conn.SetWriteDeadline(deadline)
	conn.SetReadDeadline(deadline)

	if _, err := conn.Write(packet); err != nil {
		logErrorf("write backend: %v", err)
		backendErrorsTotal.With(labelsForBackendWithStage(protocol, pool, domain, backend, "write")).Inc()
		return
	}
	labels := labelsForBackend(protocol, pool, domain, backend)
	backendPacketsSent.With(labels).Inc()
	backendBytesSent.With(labels).Add(float64(len(packet)))
	resp := make([]byte, 4096)
	n, _, err := conn.ReadFrom(resp)
	if err != nil {
		logErrorf("read backend: %v", err)
		backendErrorsTotal.With(labelsForBackendWithStage(protocol, pool, domain, backend, "read")).Inc()
		return
	}
	backendPacketsReceived.With(labels).Inc()
	backendBytesReceived.With(labels).Add(float64(n))
	if _, err := s.conn.WriteTo(resp[:n], src); err != nil {
		logErrorf("reply backend: %v", err)
		return
	}
	frontendPacketsOut.Inc()
	frontendBytesOut.Add(float64(n))
}

func main() {
	configPath := flag.String("config", "lb.yaml", "path to YAML config")
	flag.Parse()

	cfg, err := LoadConfig(*configPath)
	if err != nil {
		initLogger("") // ensure logger initialized for error path
		logErrorf("load config: %v", err)
		os.Exit(1)
	}

	initLogger(cfg.Logging.Level)

	if cfg.Global.MetricsListen != "" {
		go func() {
			if err := startMetricsServer(cfg.Global.MetricsListen); err != nil {
				logErrorf("metrics server: %v", err)
			}
		}()
	}

	s, err := newServer(cfg)
	if err != nil {
		logErrorf("init server: %v", err)
		os.Exit(1)
	}

	logInfof("listening on %s", cfg.Global.ListenAddress)
	logInfof("configured %d pool(s)", len(s.pools))
	for _, p := range s.pools {
		logDebugf("%s pool %q suffix=%q backends=%d", p.protocol, p.name, p.domainSuffix, len(p.backends))
	}

	if s.sessionTracker != nil {
		s.sessionTracker.startSessionJanitor()
	}

	if err := s.serve(); err != nil {
		logErrorf("serve error: %v", err)
		os.Exit(1)
	}
}

