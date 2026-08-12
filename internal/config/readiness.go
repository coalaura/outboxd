package config

import (
	"errors"
	"strings"
)

// IsReady reports configuration options that must be corrected before serving.
func (cfg *Config) IsReady() error {
	var problems []error

	if strings.HasSuffix(cfg.Server.Domain, ".invalid") {
		problems = append(problems, errors.New("replace server.domain with the sending domain"))
	}

	if strings.HasSuffix(cfg.Server.Hostname, ".invalid") {
		problems = append(problems, errors.New("replace server.hostname with the public SMTP hostname"))
	}

	if cfg.DNS.PublicIPv4 == "" && cfg.DNS.PublicIPv6 == "" {
		problems = append(problems, errors.New("configure at least one public sending IP"))
	}

	if len(cfg.Users) == 0 {
		problems = append(problems, errors.New("configure at least one SMTP user"))
	}

	enabled := 0

	for i := range cfg.Users {
		if cfg.Users[i].Enabled {
			enabled++
		}
	}

	if enabled == 0 {
		problems = append(problems, errors.New("configure at least one enabled SMTP user"))
	}

	if cfg.TLS.Mode == "self_signed" && !cfg.TLS.AllowSelfSignedServing {
		problems = append(problems, errors.New("tls.mode=self_signed requires tls.allow_self_signed_serving=true before serving"))
	}

	return errors.Join(problems...)
}

// Warnings reports non-fatal deliverability problems.
func (cfg *Config) Warnings() []string {
	var warnings []string

	if cfg.TLS.Mode == "self_signed" {
		warnings = append(warnings, "tls.mode is self_signed (development only); ordinary SMTP clients will not trust the certificate — use tls.mode=files with a publicly trusted certificate in production")
	}

	if cfg.DNS.DMARC == "none" {
		warnings = append(warnings, `dmarc_policy is "none"; stage to quarantine then reject after verifying SPF/DKIM alignment via aggregate reports`)
	}

	if cfg.DNS.ReportURI == "" {
		warnings = append(warnings, "dns.dmarc_report_uri is empty; you will receive no DMARC reports and have no view of failures")
	}

	if cfg.Delivery.TLSMode == "opportunistic" {
		warnings = append(warnings, "delivery.tls_mode is opportunistic; destinations without STARTTLS may receive plaintext when allow_plaintext is true")
	}

	if cfg.Delivery.TLSMode == "opportunistic_insecure" {
		warnings = append(warnings, "delivery.tls_mode is opportunistic_insecure; certificate verification is disabled for STARTTLS — development/legacy only")
	}

	if cfg.Server.Domain == cfg.Server.Hostname {
		warnings = append(warnings, "server.hostname equals server.domain; prefer a dedicated sending subdomain when the parent domain has other senders")
	}

	return warnings
}
