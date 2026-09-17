// Package netcanon owns the canonical-hostname rule shared by every component
// that accepts a network host: the server composition and the deployment
// operator import this single implementation; neither may maintain a second
// one.
package netcanon

import (
	"net"
	"strings"
)

// ValidCanonicalHost reports whether value is a lowercase DNS hostname (no
// trailing dot, per-label length and character limits) or a canonical IP
// literal. It is shared by server configuration and by the deployment
// operator, which must never maintain a second implementation of the rule.
func ValidCanonicalHost(value string) bool {
	if value == "" || value != strings.ToLower(value) || strings.HasSuffix(value, ".") {
		return false
	}
	if parsed := net.ParseIP(value); parsed != nil {
		return parsed.String() == value
	}
	if strings.Trim(value, "0123456789.") == "" {
		return false
	}
	if len(value) > 253 {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '-' {
				continue
			}
			return false
		}
	}
	return true
}
