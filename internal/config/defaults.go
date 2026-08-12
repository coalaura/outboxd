package config

import (
	"slices"
	"strings"
)

func (cfg *Config) applyDefaults() {
	if !slices.ContainsFunc(cfg.DKIM.Headers, func(header string) bool {
		return strings.EqualFold(strings.TrimSpace(header), "Sender")
	}) {
		cfg.DKIM.Headers = append(cfg.DKIM.Headers, "Sender")
	}

	if cfg.Server.DisableSubmission {
		cfg.Server.SubmissionAddr = ""
	}

	if cfg.Server.DisableImplicitTLS {
		cfg.Server.ImplicitTLSAddr = ""
	}

	if cfg.Delivery.TLSMode == "" {
		cfg.Delivery.TLSMode = "required"
	}

	if cfg.DNS.DMARC == "" {
		cfg.DNS.DMARC = "none"
	}

	if cfg.DNS.OutputFile == "" {
		cfg.DNS.OutputFile = "dns-records.txt"
	}
}

// Default returns the default config without an example password hash.
func Default() *Config {
	var allowPlain bool

	return &Config{
		Server: Server{
			Hostname:                "mail.example.invalid",
			Domain:                  "example.invalid",
			MaxMessageBytes:         25 << 20,
			MaxRecipients:           100,
			MaxMessagesPerHour:      1000,
			MaxRecipientsPerHour:    10000,
			ReadTimeout:             "5m",
			WriteTimeout:            "5m",
			DataDirectory:           "./data",
			SubmissionAddr:          ":587",
			ImplicitTLSAddr:         ":465",
			MaxConnections:          256,
			MaxConnectionsPerIP:     16,
			AuthWorkers:             4,
			MaxQueueMessages:        10000,
			MaxQueueBytes:           10 << 30,
			MaxQueueMessagesPerUser: 1000,
			MaxQueueBytesPerUser:    1 << 30,
			MaxSpoolBytes:           16 << 30,
			SpoolEmergencyBytes:     512 << 20,
			MinFreeDiskBytes:        1 << 30,
			DeadRetention:           "720h",
			CorruptRetention:        "336h",
		},
		TLS: TLS{
			Mode:            "self_signed",
			CertificateFile: "tls/server.crt",
			PrivateKeyFile:  "tls/server.key",
			MinimumVersion:  "1.2",
		},
		DKIM: DKIM{
			Selector:       "mail",
			PrivateKeyFile: "dkim/mail.key",
			Headers: []string{
				"From",
				"Sender",
				"To",
				"Cc",
				"Subject",
				"Date",
				"Message-ID",
				"MIME-Version",
				"Content-Type",
				"Content-Transfer-Encoding",
				"Reply-To",
			},
		},
		Delivery: Delivery{
			TLSMode:               "required",
			AllowPlaintext:        &allowPlain,
			MaxAttempts:           15,
			MaximumLifetime:       "120h",
			InitialRetryDelay:     "5m",
			MaximumRetryDelay:     "8h",
			DomainConcurrency:     2,
			GlobalConcurrency:     16,
			UserConcurrency:       2,
			DNSTimeout:            "30s",
			AttemptTimeout:        "30m",
			MaxMXCandidates:       10,
			MaxIPCandidatesPerMX:  8,
			ConnectionTimeout:     "30s",
			CommandTimeout:        "5m",
			SubmissionTimeout:     "12m",
			RequireValidMXTLSCert: true,
		},
		DNS: DNS{
			DMARC:      "none",
			OutputFile: "dns-records.txt",
		},
		Users: nil,
	}
}
