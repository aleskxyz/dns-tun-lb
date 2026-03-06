package main

import (
	"encoding/base32"
	"strings"

	"github.com/miekg/dns"
)

// MatchDomainSuffix reports whether qname matches the given domain suffix.
// It matches: exact (e.g. web.test.com) or any subdomain depth (e.g. sub.web.test.com, a.b.web.test.com).
// It does not match: parent domain (e.g. test.com when suffix is web.test.com).
// qname may have a trailing dot. Matching is case-insensitive.
func MatchDomainSuffix(qname, suffix string) bool {
	name := strings.ToLower(strings.TrimSuffix(qname, "."))
	suffix = strings.ToLower(suffix)
	if suffix == "" {
		return false
	}
	if name == suffix {
		return true
	}
	return strings.HasSuffix(name, "."+suffix)
}

// extractDNSTTSessionID returns the 8-byte ClientID from the QNAME prefix for consistent hashing.
// Returns (nil, false) if the prefix is empty, not valid base32, or decodes to fewer than 8 bytes.
func extractDNSTTSessionID(msg *dns.Msg, suffix string) ([]byte, bool) {
	if len(msg.Question) == 0 {
		return nil, false
	}
	q := msg.Question[0]
	name := strings.TrimSuffix(q.Name, ".")
	suffix = strings.ToLower(suffix)

	lowerName := strings.ToLower(name)
	var prefix string
	if strings.HasSuffix(lowerName, "."+suffix) {
		prefix = name[:len(name)-(len(suffix)+1)]
	} else if strings.EqualFold(lowerName, suffix) {
		prefix = ""
	} else {
		return nil, false
	}

	if prefix == "" {
		return nil, false
	}

	labels := strings.Split(prefix, ".")
	var sb strings.Builder
	for _, l := range labels {
		if l == "" {
			continue
		}
		sb.WriteString(l)
	}

	encoded := strings.ToLower(sb.String())
	if encoded == "" {
		return nil, false
	}

	dec := base32.StdEncoding.WithPadding(base32.NoPadding)
	buf, err := dec.DecodeString(strings.ToUpper(encoded))
	if err != nil {
		return nil, false
	}
	if len(buf) < 8 {
		return nil, false
	}
	id := make([]byte, 8)
	copy(id, buf[:8])
	return id, true
}

