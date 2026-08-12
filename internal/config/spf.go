package config

import (
	"fmt"
	"net/netip"
	"strings"
)

// ExpectedSPF returns the effective policy emitted by DNS generation.
func (cfg *Config) ExpectedSPF() string {
	var b strings.Builder

	b.WriteString("v=spf1")

	if cfg.DNS.PublicIPv4 != "" {
		ip, err := netip.ParseAddr(cfg.DNS.PublicIPv4)
		if err == nil && ip.Is4() {
			fmt.Fprintf(&b, " ip4:%s", ip.String())
		}
	}

	if cfg.DNS.PublicIPv6 != "" {
		fmt.Fprintf(&b, " ip6:%s", cfg.DNS.PublicIPv6)
	}

	for _, include := range cfg.DNS.SPFIncludes {
		fmt.Fprintf(&b, " include:%s", strings.ToLower(strings.TrimSuffix(strings.TrimSpace(include), ".")))
	}

	b.WriteString(" -all")

	return b.String()
}
