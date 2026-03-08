package main

import (
	"github.com/miekg/dns"
)

// extractDNSTTSessionID returns the first 8 bytes of the base32-decoded QNAME prefix, or (nil, false) if invalid or too short.
func extractDNSTTSessionID(msg *dns.Msg, suffix string) ([]byte, bool) {
	buf, ok := decodeQnamePrefixPayload(msg, suffix)
	if !ok || len(buf) < 8 {
		return nil, false
	}
	id := make([]byte, 8)
	copy(id, buf[:8])
	return id, true
}

