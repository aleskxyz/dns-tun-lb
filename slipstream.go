package main

import (
	"github.com/miekg/dns"
)

// extractSlipstreamSessionID returns an 8-byte connection ID from the QUIC payload in the QNAME for consistent hashing.
// We use DCID (Destination Connection ID) for both long and short headers so that the same QUIC connection
// always hashes to the same backend (same approach as QUIC LB in RFC 9439). Using SCID for long and DCID for short would yield two different values
// for the same connection (RFC 9000: SCID and DCID are chosen by different endpoints), causing handshake
// packets to land on one backend and 1-RTT packets on another and breaking Slipstream+SSH and other stateful use.
// Wire format: RFC 9000; slipstream uses 8-byte CIDs (slipstream_stateless_packet.c). Returns (nil, false) if too short or invalid.
func extractSlipstreamSessionID(msg *dns.Msg, suffix string) ([]byte, bool) {
	payload, ok := decodeQnamePrefixPayload(msg, suffix)
	if !ok || len(payload) < 7 {
		return nil, false
	}

	id := make([]byte, 8)
	if payload[0]&0x80 != 0 {
		// Long header: DCID length at 5, DCID at 6..6+dcidLen, SCID length at 6+dcidLen, SCID at 7+dcidLen..
		dcidLen := int(payload[5])
		if len(payload) < 6+dcidLen+1 {
			return nil, false
		}
		if dcidLen > 0 {
			dcid := payload[6 : 6+dcidLen]
			copy(id, dcid)
			return id, true
		}
		scidLen := int(payload[6+dcidLen])
		const maxCIDLen = 20 // RFC 9000
		if scidLen <= 0 || scidLen > maxCIDLen || len(payload) < 7+dcidLen+scidLen {
			return nil, false
		}
		scid := payload[7+dcidLen : 7+dcidLen+scidLen]
		copy(id, scid)
		return id, true
	}
	// Short header: DCID at [1:9] (slipstream uses fixed 8-byte DCID)
	if len(payload) < 9 {
		return nil, false
	}
	copy(id, payload[1:9])
	return id, true
}
