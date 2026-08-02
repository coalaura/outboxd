package config

import (
	"crypto/tls"
	"strings"
	"time"
)

// MinimumTLSVersion returns the configured floor for the submission listeners.
func (cfg *Config) MinimumTLSVersion() uint16 {
	if cfg.TLS.MinimumVersion == "1.3" {
		return tls.VersionTLS13
	}

	return tls.VersionTLS12
}

// Allows reports whether the user may send as the given address. Exact entries
// compare local-parts byte-for-byte and domains case-insensitively. Wildcards
// authorize every local-part in their domain.
func (u User) Allows(address string) bool {
	address = strings.TrimSpace(address)

	at := strings.LastIndexByte(address, '@')
	if at <= 0 || at == len(address)-1 {
		return false
	}

	local := address[:at]
	domain := address[at+1:]

	for _, sender := range u.AllowedSenders {
		if strings.HasPrefix(sender, "*@") && strings.EqualFold(sender[2:], domain) {
			return true
		}

		senderAt := strings.LastIndexByte(sender, '@')
		if senderAt > 0 && sender[:senderAt] == local && strings.EqualFold(sender[senderAt+1:], domain) {
			return true
		}
	}

	return false
}

// Duration parses a duration that Validate already accepted.
func Duration(value string) time.Duration {
	duration, _ := time.ParseDuration(value)

	return duration
}
