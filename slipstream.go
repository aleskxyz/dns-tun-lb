package main

import (
	"github.com/miekg/dns"
)

// extractSlipstreamSessionID returns an 8-byte connection ID from the QUIC payload for hashing. Uses DCID (or SCID if DCID empty) for long header, DCID for short, so the same connection hashes to one backend.
func extractSlipstreamSessionID(msg *dns.Msg, suffix string) ([]byte, bool) {
	payload, ok := decodeQnamePrefixPayload(msg, suffix)
	if !ok || len(payload) < 7 {
		return nil, false
	}

	id := make([]byte, 8)
	if payload[0]&0x80 != 0 {
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
		const maxCIDLen = 20
		if scidLen <= 0 || scidLen > maxCIDLen || len(payload) < 7+dcidLen+scidLen {
			return nil, false
		}
		scid := payload[7+dcidLen : 7+dcidLen+scidLen]
		copy(id, scid)
		return id, true
	}
	if len(payload) < 9 {
		return nil, false
	}
	copy(id, payload[1:9])
	return id, true
}

// decodeSlipstreamQUICLBServerID decodes the QUIC-LB server_id from the packet. QUIC-LB CIDs use first octet (config_rotation<<6)|(length-1) with config_rotation=0 and length>=2; server_id is at DCID index 1. Short header: DCID at payload[1:]. Long header: DCID at payload[6:6+dcidLen]. Returns (0, false) when not QUIC-LB so the LB can fall back to hash.
func decodeSlipstreamQUICLBServerID(msg *dns.Msg, suffix string) (serverID uint8, ok bool) {
	serverID, ok, _ = decodeSlipstreamQUICLBServerIDDebug(msg, suffix)
	return serverID, ok
}

// decodeSlipstreamQUICLBServerIDDebug is for debug logging: returns server_id, ok, and a human-readable reason when ok is false.
func decodeSlipstreamQUICLBServerIDDebug(msg *dns.Msg, suffix string) (serverID uint8, ok bool, reason string) {
	payload, okPayload := decodeQnamePrefixPayload(msg, suffix)
	if !okPayload {
		return 0, false, "qname_decode_fail"
	}
	if len(payload) < 7 {
		return 0, false, "payload_too_short"
	}
	flags := payload[0]
	if flags&0x80 != 0 {
		// Long header: DCID at payload[6 : 6+dcidLen]
		dcidLen := int(payload[5])
		if dcidLen < 2 {
			return 0, false, "long_header_dcid_len<2"
		}
		if len(payload) < 6+dcidLen {
			return 0, false, "long_header_payload_short"
		}
		// QUIC-LB: first octet (config_rotation<<6)|(length-1); config_rotation=0, length>=2
		first := payload[6]
		if (first&0xC0) != 0 || (first&0x3F) < 1 {
			return 0, false, "long_header_dcid_not_quiclb"
		}
		return payload[7], true, ""
	}
	// Short header: DCID at payload[1:]
	first := payload[1]
	if (first&0xC0) != 0 || (first&0x3F) < 1 || len(payload) < 3 {
		return 0, false, "short_header_dcid_not_quiclb"
	}
	return payload[2], true, ""
}
