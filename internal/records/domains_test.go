package records

import (
	"strings"
	"testing"

	"github.com/coalaura/outboxd/internal/config"
)

func TestRecordsForEveryDomain(t *testing.T) {
	cfg := config.Default()

	cfg.Server.Hostname = "mail.example.com"
	cfg.Domains[0].Name = "example.com"
	cfg.Domains = append(cfg.Domains, config.Domain{Name: "example.net", DKIM: config.DKIM{Selector: "other"}})
	cfg.DNS.PublicIPv4 = "203.0.113.1"
	cfg.DNS.ReportURI = "mailto:dmarc@reports.example.org"
	cfg.DNS.TLSRPTURI = "mailto:tls@reports.example.org"
	cfg.Users = []config.User{{AllowedSenders: []string{"alice@example.net", "*@news.example.net"}}}

	keys := map[string]string{"example.com": "v=DKIM1; p=first", "example.net": "v=DKIM1; p=second"}

	records := Build(cfg, keys)

	values := make(map[string]string, len(records))

	for _, record := range records {
		key := record.Name + " " + record.Type
		if _, exists := values[key]; exists {
			t.Fatalf("duplicate record: %s", key)
		}

		values[key] = record.Value
	}

	if values["mail._domainkey.example.com. TXT"] != keys["example.com"] || values["other._domainkey.example.net. TXT"] != keys["example.net"] {
		t.Fatalf("wrong per-domain keys: %v", values)
	}

	for _, domain := range cfg.Domains {
		if !strings.HasPrefix(values[domain.Name+". TXT"], "v=spf1 ") || !strings.HasPrefix(values["_dmarc."+domain.Name+". TXT"], "v=DMARC1;") || !strings.HasPrefix(values["_smtp._tls."+domain.Name+". TXT"], "v=TLSRPTv1;") {
			t.Fatalf("missing policy records for %s: %v", domain.Name, values)
		}

		if values[domain.Name+"._report._dmarc.reports.example.org. TXT"] != "v=DMARC1" {
			t.Fatalf("missing reporting authorization for %s", domain.Name)
		}
	}

	if !strings.HasPrefix(values["news.example.net. TXT"], "v=spf1 ") {
		t.Fatal("missing sender subdomain SPF")
	}

	delete(keys, "example.net")

	_, _, err := Write(cfg, keys)
	if err == nil || !strings.Contains(err.Error(), "example.net") {
		t.Fatalf("Write with missing key: %v", err)
	}
}
