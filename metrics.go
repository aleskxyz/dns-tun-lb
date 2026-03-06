package main

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	dnsRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dns_lb_requests_total",
			Help: "Total incoming DNS requests, by protocol.",
		},
		[]string{"protocol"},
	)
	dnsRoutedRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dns_lb_routed_requests_total",
			Help: "Total DNS requests routed to tunnel backends, by protocol and pool.",
		},
		[]string{"protocol", "pool"},
	)
	dnsForwardedRequestsTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dns_lb_forwarded_requests_total",
			Help: "Total DNS requests forwarded to upstream resolvers (non-tunnel).",
		},
	)
	dnsDroppedRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dns_lb_dropped_requests_total",
			Help: "Total DNS requests dropped at the load balancer, by reason.",
		},
		[]string{"reason"},
	)
	frontendBytesIn = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dns_lb_frontend_bytes_in_total",
			Help: "Total bytes received on the frontend UDP socket.",
		},
	)
	frontendBytesOut = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dns_lb_frontend_bytes_out_total",
			Help: "Total bytes sent on the frontend UDP socket.",
		},
	)
	frontendPacketsIn = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dns_lb_frontend_packets_in_total",
			Help: "Total UDP packets received on the frontend.",
		},
	)
	frontendPacketsOut = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dns_lb_frontend_packets_out_total",
			Help: "Total UDP packets sent on the frontend.",
		},
	)
	parseErrorsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dns_lb_parse_errors_total",
			Help: "Total DNS unpack or parse errors, by stage.",
		},
		[]string{"stage"},
	)
	unsupportedQueriesTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dns_lb_unsupported_queries_total",
			Help: "Total non-TXT queries routed to tunnel pools (by QTYPE); requests still sent to backend.",
		},
		[]string{"qtype"},
	)

	backendBytesSent = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dns_lb_backend_bytes_sent_total",
			Help: "Total bytes sent to backends, by protocol/pool/domain/backend.",
		},
		[]string{"protocol", "pool", "domain", "backend_id"},
	)
	backendBytesReceived = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dns_lb_backend_bytes_received_total",
			Help: "Total bytes received from backends, by protocol/pool/domain/backend.",
		},
		[]string{"protocol", "pool", "domain", "backend_id"},
	)
	backendPacketsSent = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dns_lb_backend_packets_sent_total",
			Help: "Total packets sent to backends, by protocol/pool/domain/backend.",
		},
		[]string{"protocol", "pool", "domain", "backend_id"},
	)
	backendPacketsReceived = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dns_lb_backend_packets_received_total",
			Help: "Total packets received from backends, by protocol/pool/domain/backend.",
		},
		[]string{"protocol", "pool", "domain", "backend_id"},
	)
	backendRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dns_lb_backend_requests_total",
			Help: "Total DNS requests routed to backends, by protocol/pool/domain/backend.",
		},
		[]string{"protocol", "pool", "domain", "backend_id"},
	)
	backendErrorsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dns_lb_backend_errors_total",
			Help: "Total backend errors, by protocol/pool/domain/backend/stage.",
		},
		[]string{"protocol", "pool", "domain", "backend_id", "stage"},
	)
	backendSessionsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dns_lb_backend_sessions_total",
			Help: "Total distinct sessions observed per backend, by protocol/pool/domain/backend.",
		},
		[]string{"protocol", "pool", "domain", "backend_id"},
	)
	backendSessionsActive = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "dns_lb_backend_sessions_active",
			Help: "Approximate number of active sessions per backend, by protocol/pool/domain/backend.",
		},
		[]string{"protocol", "pool", "domain", "backend_id"},
	)
)

func init() {
	prometheus.MustRegister(
		dnsRequestsTotal,
		dnsRoutedRequestsTotal,
		dnsForwardedRequestsTotal,
		dnsDroppedRequestsTotal,
		frontendBytesIn,
		frontendBytesOut,
		frontendPacketsIn,
		frontendPacketsOut,
		parseErrorsTotal,
		unsupportedQueriesTotal,

		backendBytesSent,
		backendBytesReceived,
		backendPacketsSent,
		backendPacketsReceived,
		backendRequestsTotal,
		backendErrorsTotal,
		backendSessionsTotal,
		backendSessionsActive,
	)
}

// labelsForBackend builds the common label set for per-backend metrics.
func labelsForBackend(protocol, pool, domain string, backend BackendConfig) prometheus.Labels {
	return prometheus.Labels{
		"protocol":   protocol,
		"pool":       pool,
		"domain":     domain,
		"backend_id": backend.ID,
	}
}

// labelsForBackendWithStage extends the backend label set with an error stage.
func labelsForBackendWithStage(protocol, pool, domain string, backend BackendConfig, stage string) prometheus.Labels {
	labels := labelsForBackend(protocol, pool, domain, backend)
	labels["stage"] = stage
	return labels
}

// sessionTracker tracks approximate active sessions per backend with a TTL.
type sessionTracker struct {
	mu       sync.Mutex
	sessions map[string]time.Time
	ttl      time.Duration
}

func newSessionTracker(ttl time.Duration) *sessionTracker {
	return &sessionTracker{
		sessions: make(map[string]time.Time),
		ttl:      ttl,
	}
}

// observeSession records that a session is active on a backend. If it's a new
// session key, increments total and active gauges.
func (t *sessionTracker) observeSession(protocol, pool, domain string, backend BackendConfig, sid []byte) {
	if len(sid) == 0 {
		return
	}
	key := sessionKey(protocol, pool, domain, backend, sid)
	now := time.Now()

	t.mu.Lock()
	defer t.mu.Unlock()

	_, existed := t.sessions[key]
	t.sessions[key] = now

	if !existed {
		labels := labelsForBackend(protocol, pool, domain, backend)
		backendSessionsTotal.With(labels).Inc()
		backendSessionsActive.With(labels).Inc()
	}
}

// reapExpired decrements active sessions for entries that have been idle past
// the TTL.
func (t *sessionTracker) reapExpired() {
	now := time.Now()

	t.mu.Lock()
	defer t.mu.Unlock()

	for key, last := range t.sessions {
		if now.Sub(last) > t.ttl {
			// Parse labels back out of key.
			protocol, pool, domain, backendID := parseSessionKey(key)
			backendSessionsActive.With(prometheus.Labels{
				"protocol":   protocol,
				"pool":       pool,
				"domain":     domain,
				"backend_id": backendID,
			}).Dec()
			delete(t.sessions, key)
		}
	}
}

// startSessionJanitor runs a background goroutine to periodically reap expired sessions.
func (t *sessionTracker) startSessionJanitor() {
	if t == nil {
		return
	}
	go func() {
		ticker := time.NewTicker(t.ttl / 2)
		defer ticker.Stop()
		for range ticker.C {
			t.reapExpired()
		}
	}()
}

// sessionKeySep is used to join key parts; must not appear in protocol/pool/domain/backend_id.
const sessionKeySep = "\x00"

// sessionKey encodes protocol/pool/domain/backend/session into a string key.
func sessionKey(protocol, pool, domain string, backend BackendConfig, sid []byte) string {
	// Sep must not appear in labels so parseSessionKey is unambiguous.
	return protocol + sessionKeySep + pool + sessionKeySep + domain + sessionKeySep + backend.ID + sessionKeySep + string(sid)
}

// parseSessionKey decodes a key created by sessionKey (ignoring session id).
func parseSessionKey(key string) (protocol, pool, domain, backendID string) {
	parts := strings.SplitN(key, sessionKeySep, 5)
	if len(parts) < 4 {
		return "", "", "", ""
	}
	return parts[0], parts[1], parts[2], parts[3]
}

// startMetricsServer starts an HTTP server exposing Prometheus metrics.
func startMetricsServer(addr string) error {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	return http.ListenAndServe(addr, mux)
}

