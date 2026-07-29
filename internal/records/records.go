package records

import (
	"bytes"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/coalaura/outboxd/internal/config"
	"github.com/coalaura/outboxd/internal/disk"
)

const maxString = 255

// Record is a single DNS entry the operator has to publish.
type Record struct {
	Name    string
	Type    string
	Value   string
	Purpose string
}

// Build returns every DNS record needed for the configured domain.
func Build(cfg *config.Config, dkim string) []Record {
	hostname := cfg.Server.Hostname + "."
	domain := cfg.Server.Domain + "."

	records := make([]Record, 0, 6)

	if cfg.DNS.PublicIPv4 != "" {
		records = append(records, Record{
			Name:    hostname,
			Type:    "A",
			Value:   cfg.DNS.PublicIPv4,
			Purpose: "Public IPv4 address of the SMTP hostname",
		})
	}

	if cfg.DNS.PublicIPv6 != "" {
		records = append(records, Record{
			Name:    hostname,
			Type:    "AAAA",
			Value:   cfg.DNS.PublicIPv6,
			Purpose: "Public IPv6 address of the SMTP hostname",
		})
	}

	records = append(records, Record{
		Name:    domain,
		Type:    "TXT",
		Value:   spf(cfg),
		Purpose: "SPF; authorizes this server to send for the domain and rejects everything else",
	})

	records = append(records, Record{
		Name:    hostname,
		Type:    "TXT",
		Value:   spf(cfg),
		Purpose: "SPF for the EHLO name; receivers check the HELO identity separately from the envelope sender",
	})

	records = append(records, Record{
		Name:    fmt.Sprintf("%s._domainkey.%s", cfg.DKIM.Selector, domain),
		Type:    "TXT",
		Value:   dkim,
		Purpose: "DKIM public key matching the generated private key",
	})

	records = append(records, Record{
		Name:    "_dmarc." + domain,
		Type:    "TXT",
		Value:   dmarc(cfg),
		Purpose: "DMARC policy; \"quarantine\" is a safe default; move to \"reject\" once reports look clean",
	})

	for _, host := range external(cfg) {
		records = append(records, Record{
			Name:    fmt.Sprintf("%s_report._dmarc.%s.", domain, host),
			Type:    "TXT",
			Value:   "v=DMARC1",
			Purpose: fmt.Sprintf("authorizes %s to receive DMARC reports for %s", host, cfg.Server.Domain),
		})
	}

	if cfg.DNS.ReportURI != "" {
		records = append(records, Record{
			Name:    "_smtp._tls." + domain,
			Type:    "TXT",
			Value:   fmt.Sprintf("v=TLSRPTv1; rua=%s", cfg.DNS.ReportURI),
			Purpose: "optional TLS reporting endpoint",
		})
	}

	return records
}

// Write renders the DNS instructions next to the other generated files.
func Write(cfg *config.Config, dkim string) (string, []byte, error) {
	var buffer bytes.Buffer

	buffer.Grow(4096)

	fmt.Fprintf(&buffer, "DNS setup for %s (%s)\n", cfg.Server.Domain, time.Now().Format(time.RFC3339))

	buffer.WriteString("- Outbound TCP port 25 (sending mail) must be open\n")
	buffer.WriteString("- Inbound TCP port 465 (implicit TLS) must be open\n")
	buffer.WriteString("- Inbound TCP port 587 (STARTTLS) must be open\n")

	if cfg.DNS.PublicIPv4 != "" {
		fmt.Fprintf(&buffer, "- PTR for %s must resolve to %s, and %s must resolve back to %s\n", cfg.DNS.PublicIPv4, cfg.Server.Hostname, cfg.Server.Hostname, cfg.DNS.PublicIPv4)
	}

	if cfg.DNS.PublicIPv6 != "" {
		fmt.Fprintf(&buffer, "- PTR for %s must resolve to %s; drop the AAAA record until it does\n", cfg.DNS.PublicIPv6, cfg.Server.Hostname)
	}

	buffer.WriteString("- PTR records are set at the hosting provider, not in this zone\n")
	fmt.Fprintf(&buffer, "- %s needs an MX pointing at a mailbox that accepts bounces and replies;\n  receivers reject mail whose envelope sender cannot be bounced to\n", cfg.Server.Domain)
	buffer.WriteString("- TXT values above 255 characters are shown pre-split; keep the quoting as-is\n")

	if cfg.TLS.Mode == "self_signed" {
		buffer.WriteString("- Replace self-signed submission certificate\n")
	}

	records := Build(cfg, dkim)

	for i, record := range records {
		buffer.WriteByte('\n')

		fmt.Fprintf(&buffer, "%d. %s\n", i+1, record.Purpose)
		fmt.Fprintf(&buffer, "  name  %s\n", record.Name)
		fmt.Fprintf(&buffer, "  type  %s\n", record.Type)

		if record.Type == "TXT" {
			fmt.Fprintf(&buffer, "  value %s\n", quote(record.Value))
		} else {
			fmt.Fprintf(&buffer, "  value %s\n", record.Value)
		}
	}

	path := cfg.ResolvePath(cfg.DNS.OutputFile)
	body := buffer.Bytes()

	return path, body, disk.Write(path, body, 0644)
}

func quote(value string) string {
	if len(value) <= maxString {
		return strconv.Quote(value)
	}

	var builder strings.Builder

	for start := 0; start < len(value); start += maxString {
		if start > 0 {
			builder.WriteByte(' ')
		}

		builder.WriteString(strconv.Quote(value[start:min(start+maxString, len(value))]))
	}

	return builder.String()
}

func spf(cfg *config.Config) string {
	var builder strings.Builder

	builder.WriteString("v=spf1")

	if cfg.DNS.PublicIPv4 != "" {
		fmt.Fprintf(&builder, " ip4:%s", cfg.DNS.PublicIPv4)
	}

	if cfg.DNS.PublicIPv6 != "" {
		fmt.Fprintf(&builder, " ip6:%s", cfg.DNS.PublicIPv6)
	}

	builder.WriteString(" -all")

	return builder.String()
}

func dmarc(cfg *config.Config) string {
	var builder strings.Builder

	fmt.Fprintf(&builder, "v=DMARC1; p=%s; sp=%s; np=reject; adkim=r; aspf=r", cfg.DNS.DMARC, cfg.DNS.DMARC)

	if cfg.DNS.ReportURI != "" {
		fmt.Fprintf(&builder, "; rua=%s", cfg.DNS.ReportURI)
	}

	return builder.String()
}

func external(cfg *config.Config) []string {
	var domains []string

	for uri := range strings.SplitSeq(cfg.DNS.ReportURI, ",") {
		address, ok := strings.CutPrefix(strings.TrimSpace(uri), "mailto:")
		if !ok {
			continue
		}

		address, _, _ = strings.Cut(address, "!")

		at := strings.LastIndexByte(address, '@')
		if at < 0 {
			continue
		}

		host := strings.ToLower(strings.TrimSuffix(address[at+1:], "."))

		if host == "" || host == cfg.Server.Domain || strings.HasSuffix(host, "."+cfg.Server.Domain) {
			continue
		}

		if !slices.Contains(domains, host) {
			domains = append(domains, host)
		}
	}

	return domains
}
