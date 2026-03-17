package main

import (
	"bytes"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/miekg/dns"
)

var noizBase32Encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

func extractNoizdnsSessionID(msg *dns.Msg, suffix string) ([]byte, bool) {
	payload, ok := decodeNoizdnsPayloadFromQname(msg, suffix)
	if !ok || len(payload) < 8 {
		return nil, false
	}
	id := make([]byte, 8)
	copy(id, payload[:8])
	return id, true
}

func decodeNoizdnsPayloadFromQname(msg *dns.Msg, suffix string) ([]byte, bool) {
	if len(msg.Question) == 0 {
		return nil, false
	}
	q := msg.Question[0]
	name := strings.TrimSuffix(q.Name, ".")
	lowerName := strings.ToLower(name)
	suffix = strings.ToLower(strings.TrimSuffix(suffix, "."))

	var prefix string
	if suffix == "" {
		return nil, false
	}
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

	labelsStr := strings.Split(prefix, ".")
	var labels [][]byte
	for _, l := range labelsStr {
		if l == "" {
			continue
		}
		labels = append(labels, []byte(strings.ToLower(l)))
	}
	if len(labels) == 0 {
		return nil, false
	}

	var noHyphenLabels [][]byte
	for _, lbl := range labels {
		if !containsHyphen(lbl) {
			noHyphenLabels = append(noHyphenLabels, lbl)
		}
	}

	var hexLabels [][]byte
	for _, lbl := range noHyphenLabels {
		if isAllHex(lbl) {
			hexLabels = append(hexLabels, lbl)
		}
	}
	if len(hexLabels) > 0 {
		joined := bytes.Join(hexLabels, nil)
		if hasHexIndicator(joined) {
			if buf, err := hex.DecodeString(string(joined)); err == nil {
				return buf, true
			}
		}
	}

	if len(noHyphenLabels) > 0 {
		var alphaNumLabels [][]byte
		for _, lbl := range noHyphenLabels {
			if isAllAlphaNum(lbl) {
				alphaNumLabels = append(alphaNumLabels, lbl)
			}
		}
		if len(alphaNumLabels) > 0 {
			joined := bytes.Join(alphaNumLabels, nil)
			if hasNonHexAlpha(joined) && hasHexIndicator(joined) {
				if buf, err := base36Decode(string(joined)); err == nil {
					return buf, true
				}
			}
		}
	}

	encoded := bytes.ToUpper(bytes.Join(labels, nil))
	dst := make([]byte, noizBase32Encoding.DecodedLen(len(encoded)))
	n, err := noizBase32Encoding.Decode(dst, encoded)
	if err != nil {
		return nil, false
	}
	return dst[:n], true
}

func containsHyphen(b []byte) bool {
	for _, c := range b {
		if c == '-' {
			return true
		}
	}
	return false
}

func isAllHex(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, c := range b {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func isAllAlphaNum(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, c := range b {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z')) {
			return false
		}
	}
	return true
}

func hasNonHexAlpha(b []byte) bool {
	for _, c := range b {
		if c >= 'g' && c <= 'z' {
			return true
		}
	}
	return false
}

func hasHexIndicator(b []byte) bool {
	for _, c := range b {
		if c == '0' || c == '1' || c == '8' || c == '9' {
			return true
		}
	}
	return false
}

func base36Decode(s string) ([]byte, error) {
	n, ok := new(big.Int).SetString(s, 36)
	if !ok {
		return nil, fmt.Errorf("invalid base36 string")
	}
	b := n.Bytes()
	if len(b) == 0 || b[0] != 0x01 {
		return nil, fmt.Errorf("missing base36 marker byte")
	}
	return b[1:], nil
}

