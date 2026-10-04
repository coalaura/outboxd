package check

import (
	"context"
	"testing"

	"github.com/coalaura/outboxd/internal/config"
)

func TestChecksEveryDomain(t *testing.T) {
	cfg := baseCfg()

	cfg.Domains = append(cfg.Domains, config.Domain{Name: "example.net", DKIM: config.DKIM{Selector: "other"}})
	cfg.DNS.DMARC = "reject"

	resolver := &fakeResolver{txt: map[string][]string{
		"mail._domainkey.example.com":  {"v=DKIM1; k=rsa; p=AAAA"},
		"_dmarc.example.com":           {"v=DMARC1; p=reject; rua=mailto:dmarc@reports.example.net"},
		"other._domainkey.example.net": {"v=DKIM1; k=rsa; p=BBBB"},
		"_dmarc.example.net":           {"v=DMARC1; p=reject; rua=mailto:dmarc@reports.example.net"},
	}}

	options := Options{Config: cfg, Resolver: resolver, DKIM: map[string]string{"example.com": "AAAA", "example.net": "BBBB"}}

	results := Run(context.Background(), options)

	want := map[string]bool{"dkim_example.com": false, "dkim_example.net": false, "dmarc_example.com": false, "dmarc_example.net": false}

	for _, result := range results {
		if _, exists := want[result.Name]; exists {
			if result.Level != Pass {
				t.Fatalf("%s: %s", result.Name, result.Message)
			}

			want[result.Name] = true
		}
	}

	for name, found := range want {
		if !found {
			t.Fatalf("missing result %s", name)
		}
	}

	options.DKIM["example.net"] = "AAAA"

	results = Run(context.Background(), options)

	for _, result := range results {
		if result.Name == "dkim_example.net" {
			if result.Level != Fail {
				t.Fatalf("wrong second key passed: %+v", result)
			}

			return
		}
	}

	t.Fatal("missing second domain key check")
}
