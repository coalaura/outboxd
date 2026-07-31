package records

import (
	"bytes"
	"fmt"
	"net"
	"net/url"
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

// Build returns every DNS record needed for the configured placement.
//
// At most one SPF TXT is emitted per owner name. When the EHLO hostname equals
// the envelope domain, a single SPF covers both identities.
func Build(cfg *config.Config, dkim string) []Record {
	hostname := strings.TrimSuffix(strings.ToLower(cfg.Server.Hostname), ".") + "."
	domain := strings.TrimSuffix(strings.ToLower(cfg.Server.Domain), ".") + "."

	records := make([]Record, 0, 8)

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

	// One SPF TXT per distinct owner name.
	spfOwners := spfOwnerNames(cfg)
	spfValue := spf(cfg)
	for _, owner := range spfOwners {
		purpose := "SPF; authorizes this server to send for this domain and rejects everything else"
		if owner == hostname && owner != domain {
			purpose = "SPF for the EHLO/HELO name; receivers may check HELO separately from the envelope sender"
		} else if owner != domain && owner != hostname {
			purpose = "SPF for an allowed envelope-sender domain"
		}
		records = append(records, Record{
			Name:    owner,
			Type:    "TXT",
			Value:   spfValue,
			Purpose: purpose,
		})
	}

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
		Purpose: `DMARC policy; start with p=none (monitor), then stage to "quarantine" and "reject" once reports look clean`,
	})

	// External DMARC reporting hosts need an authorization record.
	// outboxd does not accept inbound mail or DMARC reports — operators must
	// point rua at a mailbox that does.
	for _, host := range external(cfg.DNS.ReportURI, cfg.Server.Domain) {
		records = append(records, Record{
			Name:    fmt.Sprintf("%s._report._dmarc.%s.", strings.TrimSuffix(domain, "."), host),
			Type:    "TXT",
			Value:   "v=DMARC1",
			Purpose: fmt.Sprintf("authorizes %s to receive DMARC aggregate reports for %s (external destination)", host, cfg.Server.Domain),
		})
	}

	// TLS-RPT is separate from DMARC reporting.
	if tlsURI := strings.TrimSpace(cfg.DNS.TLSRPTURI); tlsURI != "" {
		records = append(records, Record{
			Name:    "_smtp._tls." + domain,
			Type:    "TXT",
			Value:   fmt.Sprintf("v=TLSRPTv1; rua=%s", tlsURI),
			Purpose: "optional SMTP TLS reporting endpoint (separate from DMARC rua)",
		})
	}

	return records
}

// Write renders the DNS instructions next to the other generated files.
func Write(cfg *config.Config, dkim string) (string, []byte, error) {
	if err := config.ValidateDMARCReportURIList(cfg.DNS.ReportURI); err != nil {
		return "", nil, fmt.Errorf("dns.dmarc_report_uri: %w", err)
	}
	if err := config.ValidateTLSReportURIList(cfg.DNS.TLSRPTURI); err != nil {
		return "", nil, fmt.Errorf("dns.tlsrpt_uri: %w", err)
	}
	var buffer bytes.Buffer

	buffer.Grow(4096)

	fmt.Fprintf(&buffer, "DNS setup for %s (%s)\n", cfg.Server.Domain, time.Now().Format(time.RFC3339))

	buffer.WriteString("- Outboxd is outbound submission + delivery only: it does not provide inbound MX\n")
	buffer.WriteString("- Outbound TCP port 25 (sending mail) must be open from this host\n")
	if addr := cfg.Server.ImplicitTLSListenAddr(); addr != "" {
		fmt.Fprintf(&buffer, "- Inbound TCP port %s (implicit TLS submission) must be open for clients\n", listenPort(addr))
	}
	if addr := cfg.Server.SubmissionListenAddr(); addr != "" {
		fmt.Fprintf(&buffer, "- Inbound TCP port %s (STARTTLS submission) must be open for clients\n", listenPort(addr))
	}
	buffer.WriteString("- Do not publish an MX for this host unless a separate mailbox accepts mail elsewhere\n")

	if cfg.DNS.PublicIPv4 != "" {
		fmt.Fprintf(&buffer, "- PTR for %s must resolve to %s, and %s must resolve back to %s (FCrDNS)\n", cfg.DNS.PublicIPv4, cfg.Server.Hostname, cfg.Server.Hostname, cfg.DNS.PublicIPv4)
	}

	if cfg.DNS.PublicIPv6 != "" {
		fmt.Fprintf(&buffer, "- PTR for %s must resolve to %s; drop the AAAA record until it does\n", cfg.DNS.PublicIPv6, cfg.Server.Hostname)
	}

	buffer.WriteString("- PTR records are set at the hosting provider, not in this zone\n")
	fmt.Fprintf(&buffer, "- Envelope-sender domain(s) need MX (or an A/AAAA implicit MX) pointing at a mailbox that accepts bounces and replies;\n  receivers reject mail whose envelope sender cannot be bounced to. outboxd itself is not that mailbox.\n")
	buffer.WriteString("- Publish exactly one SPF TXT per owner name (never two SPF records at the same name)\n")
	buffer.WriteString("- DMARC aggregate reports (rua) must go to a mailbox you control; outboxd does not ingest reports\n")
	buffer.WriteString("- External DMARC report destinations need a <org>._report._dmarc.<rua-host> authorization TXT\n")
	buffer.WriteString("- TLS-RPT (_smtp._tls) is optional and separate from DMARC rua\n")
	buffer.WriteString("- TXT values above 255 characters are shown pre-split; keep the quoting as-is\n")

	if cfg.TLS.Mode == "self_signed" {
		buffer.WriteString("- tls.mode is self_signed (development only); replace with a publicly trusted certificate for production clients\n")
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

	path, err := cfg.ResolveGeneratedPath(cfg.DNS.OutputFile)
	if err != nil {
		return "", nil, err
	}
	if err := cfg.CheckGeneratedParents(path); err != nil {
		return "", nil, err
	}
	body := buffer.Bytes()

	return path, body, disk.Write(path, body, 0644)
}

func listenPort(addr string) string {
	if _, port, err := net.SplitHostPort(addr); err == nil {
		return port
	}
	return strings.TrimPrefix(addr, ":")
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

// spfOwnerNames returns distinct DNS owner names that need an SPF TXT:
// the envelope domain, every distinct allowed-sender domain, and the HELO
// hostname when it differs from those.
func spfOwnerNames(cfg *config.Config) []string {
	domain := strings.TrimSuffix(strings.ToLower(cfg.Server.Domain), ".") + "."
	hostname := strings.TrimSuffix(strings.ToLower(cfg.Server.Hostname), ".") + "."

	var owners []string
	add := func(name string) {
		name = strings.TrimSuffix(strings.ToLower(name), ".") + "."
		if name == "." {
			return
		}
		if !slices.Contains(owners, name) {
			owners = append(owners, name)
		}
	}

	add(domain)

	for i := range cfg.Users {
		for _, sender := range cfg.Users[i].AllowedSenders {
			sender = strings.TrimSpace(sender)
			if sender == "" {
				continue
			}
			if strings.HasPrefix(sender, "*@") {
				add(sender[2:])
				continue
			}
			at := strings.LastIndexByte(sender, '@')
			if at < 0 || at == len(sender)-1 {
				continue
			}
			add(sender[at+1:])
		}
	}

	// HELO SPF only when the EHLO name is distinct from every envelope owner.
	if !slices.Contains(owners, hostname) {
		add(hostname)
	}

	return owners
}

func spf(cfg *config.Config) string {
	return cfg.ExpectedSPF()
}

func dmarc(cfg *config.Config) string {
	policy := cfg.DNS.DMARC
	if policy == "" {
		policy = "none"
	}

	var builder strings.Builder

	// DMARC default is p=none (monitor). Stage to quarantine/reject after verifying alignment.
	fmt.Fprintf(&builder, "v=DMARC1; p=%s; sp=%s; adkim=r; aspf=r", policy, policy)

	rua := strings.TrimSpace(cfg.DNS.ReportURI)
	if rua != "" {
		fmt.Fprintf(&builder, "; rua=%s", rua)
	}

	return builder.String()
}

func external(reportURI, orgDomain string) []string {
	var domains []string
	orgDomain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(orgDomain), "."))

	for _, uri := range strings.Split(reportURI, ",") {
		uri = strings.TrimSpace(uri)
		uri = trimDMARCSize(uri)
		parsed, err := url.Parse(uri)
		if err != nil {
			continue
		}

		var host string
		switch strings.ToLower(parsed.Scheme) {
		case "mailto":
			at := strings.LastIndexByte(parsed.Opaque, '@')
			if at >= 0 {
				host = parsed.Opaque[at+1:]
			}
		case "https":
			host = parsed.Hostname()
		}
		host = strings.ToLower(strings.TrimSuffix(host, "."))

		if host == "" || host == orgDomain || strings.HasSuffix(host, "."+orgDomain) {
			continue
		}

		if !slices.Contains(domains, host) {
			domains = append(domains, host)
		}
	}

	return domains
}

func trimDMARCSize(value string) string {
	bang := strings.LastIndexByte(value, '!')
	if bang < 0 || bang == len(value)-1 {
		return value
	}
	suffix := value[bang+1:]
	if unit := suffix[len(suffix)-1]; unit == 'k' || unit == 'K' || unit == 'm' || unit == 'M' || unit == 'g' || unit == 'G' || unit == 't' || unit == 'T' {
		suffix = suffix[:len(suffix)-1]
	}
	if suffix == "" {
		return value
	}
	for _, char := range suffix {
		if char < '0' || char > '9' {
			return value
		}
	}
	return value[:bang]
}
