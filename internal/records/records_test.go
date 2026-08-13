package records

import (
	"strings"
	"testing"

	"github.com/coalaura/outboxd/internal/config"
)

func TestSPFDedupeWhenHostnameEqualsDomain(t *testing.T) {
	cfg := config.Default()

	cfg.Server.Hostname = "example.com"
	cfg.Server.Domain = "example.com"
	cfg.DNS.PublicIPv4 = "203.0.113.1"

	recs := Build(cfg, "v=DKIM1; p=x")

	var spf int

	for _, r := range recs {
		if r.Type == "TXT" && strings.HasPrefix(r.Value, "v=spf1") {
			spf++

			if r.Name != "example.com." {
				t.Fatalf("unexpected SPF name %s", r.Name)
			}
		}
	}

	if spf != 1 {
		t.Fatalf("SPF count=%d want 1", spf)
	}
}

func TestSPFForSenderDomainsAndIncludes(t *testing.T) {
	cfg := config.Default()

	cfg.Server.Hostname = "mail.example.com"
	cfg.Server.Domain = "example.com"
	cfg.DNS.PublicIPv4 = "203.0.113.1"
	cfg.DNS.SPFIncludes = []string{"_spf.google.com"}
	cfg.Users = []config.User{{
		AllowedSenders: []string{"a@example.com", "*@news.example.com"},
	}}

	recs := Build(cfg, "v=DKIM1; p=x")

	owners := map[string]bool{}

	var spfVal string

	for _, r := range recs {
		if r.Type == "TXT" && strings.HasPrefix(r.Value, "v=spf1") {
			owners[r.Name] = true

			spfVal = r.Value
		}
	}

	for _, want := range []string{"example.com.", "news.example.com.", "mail.example.com."} {
		if !owners[want] {
			t.Fatalf("missing SPF owner %s in %v", want, owners)
		}
	}

	if !strings.Contains(spfVal, "include:_spf.google.com") {
		t.Fatalf("spf=%s", spfVal)
	}

	if !strings.Contains(spfVal, "ip4:203.0.113.1") {
		t.Fatalf("spf=%s", spfVal)
	}
}

func TestMappedIPv6IsNotEmittedAsIPv4(t *testing.T) {
	cfg := config.Default()

	cfg.Server.Hostname = "mail.example.com"
	cfg.Server.Domain = "example.com"
	cfg.DNS.PublicIPv4 = "::ffff:192.0.2.1"

	for _, record := range Build(cfg, "v=DKIM1; p=x") {
		if record.Type == "A" || strings.Contains(record.Value, "ip4:") {
			t.Fatalf("mapped IPv6 emitted as IPv4: %+v", record)
		}
	}
}

func TestTLSRPTSeparateFromDMARC(t *testing.T) {
	cfg := config.Default()

	cfg.Server.Hostname = "mail.example.com"
	cfg.Server.Domain = "example.com"
	cfg.DNS.ReportURI = "mailto:dmarc@example.com"
	cfg.DNS.TLSRPTURI = "mailto:tlsrpt@example.com"
	cfg.DNS.DMARC = "none"

	recs := Build(cfg, "v=DKIM1; p=x")

	var (
		dmarc  string
		tlsrpt string
	)

	for _, r := range recs {
		if strings.HasPrefix(r.Name, "_dmarc.") {
			dmarc = r.Value
		}

		if strings.HasPrefix(r.Name, "_smtp._tls.") {
			tlsrpt = r.Value
		}
	}

	if !strings.Contains(dmarc, "rua=mailto:dmarc@example.com") {
		t.Fatalf("dmarc=%s", dmarc)
	}

	if strings.Contains(dmarc, "tlsrpt") {
		t.Fatal("DMARC must not use TLSRPT URI")
	}

	if !strings.Contains(tlsrpt, "rua=mailto:tlsrpt@example.com") {
		t.Fatalf("tlsrpt=%s", tlsrpt)
	}

	if !strings.Contains(dmarc, "p=none") {
		t.Fatalf("want p=none got %s", dmarc)
	}
}

func TestExternalDMARCMailboxBangIsNotSizeSuffix(t *testing.T) {
	hosts := external("mailto:ops!alerts@reports.example.net", "example.com")
	if len(hosts) != 1 || hosts[0] != "reports.example.net" {
		t.Fatalf("external hosts=%v", hosts)
	}
}

func TestExternalDMARCHTTPSDestination(t *testing.T) {
	hosts := external("mailto:ops!alerts@reports.example.net, https://aggregate.example.org/v1!12x, https://limited.example.net/report!10M", "example.com")
	want := []string{"reports.example.net", "aggregate.example.org", "limited.example.net"}

	if len(hosts) != len(want) {
		t.Fatalf("external hosts=%v", hosts)
	}

	for i := range want {
		if hosts[i] != want[i] {
			t.Fatalf("external hosts=%v want %v", hosts, want)
		}
	}

	cfg := config.Default()

	cfg.Server.Domain = "example.com"
	cfg.DNS.ReportURI = "https://aggregate.example.org/v1/reports"

	for _, record := range Build(cfg, "v=DKIM1; p=x") {
		if record.Name == "example.com._report._dmarc.aggregate.example.org." && record.Value == "v=DMARC1" {
			return
		}
	}

	t.Fatal("missing HTTPS DMARC destination authorization record")
}

func TestInstructionsListOnlyEnabledListenerPorts(t *testing.T) {
	cfg := config.Default()

	cfg.Server.DataDirectory = t.TempDir()
	cfg.Server.DisableImplicitTLS = true
	cfg.Server.SubmissionAddr = "127.0.0.1:2525"

	_, body, err := Write(cfg, "v=DKIM1; p=x")
	if err != nil {
		t.Fatal(err)
	}

	text := string(body)
	if !strings.Contains(text, "port 2525 (STARTTLS") {
		t.Fatalf("enabled listener missing from instructions:\n%s", text)
	}

	if strings.Contains(text, "port 465") || strings.Contains(text, "implicit TLS submission") {
		t.Fatal("disabled implicit TLS listener included in instructions")
	}
}

func TestReplyRejectionMXIsConditional(t *testing.T) {
	cfg := config.Default()

	cfg.Server.Hostname = "mail.example.com"
	cfg.ReplyRejection.Domains = []string{"example.com", "news.example.com"}

	for _, record := range Build(cfg, "v=DKIM1; p=x") {
		if record.Type == "MX" {
			t.Fatalf("MX generated while disabled: %+v", record)
		}
	}

	cfg.ReplyRejection.Enabled = true

	records := Build(cfg, "v=DKIM1; p=x")

	seen := map[string]string{}

	for _, record := range records {
		if record.Type == "MX" {
			seen[record.Name] = record.Value
		}
	}

	for _, domain := range cfg.ReplyRejection.Domains {
		if seen[domain+"."] != "10 mail.example.com." {
			t.Fatalf("missing MX for %s: %v", domain, seen)
		}
	}
}
