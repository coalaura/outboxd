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

// Allows reports whether the user may send as the given address.
// Comparison is case-insensitive for both local-part and domain; the address
// placed on the SMTP wire is not modified by this check.
func (u User) Allows(address string) bool {
	address = strings.TrimSpace(address)

	at := strings.LastIndexByte(address, '@')
	if at <= 0 || at == len(address)-1 {
		return false
	}

	domain := strings.ToLower(address[at+1:])
	canon := strings.ToLower(address)

	for _, sender := range u.AllowedSenders {
		if strings.EqualFold(sender, address) || strings.ToLower(sender) == canon {
			return true
		}

		if strings.HasPrefix(sender, "*@") && strings.EqualFold(sender[2:], domain) {
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
