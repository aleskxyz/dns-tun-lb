package main

import (
	"encoding/base32"
	"strings"

	"github.com/miekg/dns"
)

// MatchDomainSuffix reports whether qname equals or is a subdomain of suffix. Case-insensitive; qname may have a trailing dot.
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

// decodeQnamePrefixPayload returns the base32-decoded QNAME prefix before the domain suffix, or (nil, false) on error.
func decodeQnamePrefixPayload(msg *dns.Msg, suffix string) ([]byte, bool) {
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
	return buf, true
}
