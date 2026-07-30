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

func TestTLSRPTSeparateFromDMARC(t *testing.T) {
	cfg := config.Default()
	cfg.Server.Hostname = "mail.example.com"
	cfg.Server.Domain = "example.com"
	cfg.DNS.ReportURI = "mailto:dmarc@example.com"
	cfg.DNS.TLSRPTURI = "mailto:tlsrpt@example.com"
	cfg.DNS.DMARC = "none"
	recs := Build(cfg, "v=DKIM1; p=x")
	var dmarc, tlsrpt string
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
