package check

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/coalaura/outboxd/internal/config"
)

type fakeResolver struct {
	ips map[string][]net.IPAddr
	ptr map[string][]string
	txt map[string][]string
	mx  map[string][]*net.MX
	err map[string]error
}

func (f *fakeResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if err, ok := f.err["ip:"+host]; ok {
		return nil, err
	}
	return f.ips[host], nil
}

func (f *fakeResolver) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	if err, ok := f.err["ptr:"+addr]; ok {
		return nil, err
	}
	return f.ptr[addr], nil
}

func (f *fakeResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if err, ok := f.err["txt:"+name]; ok {
		return nil, err
	}
	return f.txt[name], nil
}

func (f *fakeResolver) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if err, ok := f.err["mx:"+name]; ok {
		return nil, err
	}
	return f.mx[name], nil
}

func baseCfg() *config.Config {
	cfg := config.Default()
	cfg.Server.Hostname = "mail.example.com"
	cfg.Server.Domain = "example.com"
	cfg.DNS.PublicIPv4 = "203.0.113.10"
	cfg.DNS.DMARC = "none"
	cfg.DNS.ReportURI = "mailto:dmarc@reports.example.net"
	cfg.DKIM.Selector = "mail"
	cfg.Users = []config.User{{
		Username:       "alice",
		AllowedSenders: []string{"alice@example.com", "bob@news.example.com"},
		Enabled:        true,
	}}
	return cfg
}

func TestHostnameAndFCrDNSPass(t *testing.T) {
	cfg := baseCfg()
	r := &fakeResolver{
		ips: map[string][]net.IPAddr{
			"mail.example.com": {{IP: net.ParseIP("203.0.113.10")}},
		},
		ptr: map[string][]string{
			"203.0.113.10": {"mail.example.com."},
		},
		txt: map[string][]string{
			"example.com":                 {"v=spf1 ip4:203.0.113.10 -all"},
			"mail.example.com":            {"v=spf1 ip4:203.0.113.10 -all"},
			"news.example.com":            {"v=spf1 ip4:203.0.113.10 -all"},
			"mail._domainkey.example.com": {"v=DKIM1; k=rsa; p=AAAA"},
			"_dmarc.example.com":          {"v=DMARC1; p=none; rua=mailto:dmarc@reports.example.net"},
		},
		mx: map[string][]*net.MX{
			"example.com":      {{Host: "mx.example.com.", Pref: 10}},
			"news.example.com": {{Host: "mx.example.com.", Pref: 10}},
		},
	}
	results := Run(context.Background(), Options{
		Config:   cfg,
		Resolver: r,
		DKIM:     &DKIMKey{Selector: "mail", PublicKey: "AAAA"},
	})
	for _, res := range results {
		if res.Level == Fail {
			t.Fatalf("%s: %s", res.Name, res.Message)
		}
	}
	if Failed(results) {
		t.Fatal("unexpected failures")
	}
}

func TestHostnameAddressFail(t *testing.T) {
	cfg := baseCfg()
	r := &fakeResolver{
		ips: map[string][]net.IPAddr{
			"mail.example.com": {{IP: net.ParseIP("198.51.100.1")}},
		},
	}
	results := Run(context.Background(), Options{Config: cfg, Resolver: r})
	found := false
	for _, res := range results {
		if strings.HasPrefix(res.Name, "hostname_address") && res.Level == Fail {
			found = true
		}
	}
	if !found {
		t.Fatal("expected hostname_address failure")
	}
}

func TestMultipleSPFFail(t *testing.T) {
	cfg := baseCfg()
	r := &fakeResolver{
		ips: map[string][]net.IPAddr{
			"mail.example.com": {{IP: net.ParseIP("203.0.113.10")}},
		},
		ptr: map[string][]string{"203.0.113.10": {"mail.example.com."}},
		txt: map[string][]string{
			"example.com": {
				"v=spf1 ip4:203.0.113.10 -all",
				"v=spf1 ip4:198.51.100.1 -all",
			},
			"mail.example.com":            {"v=spf1 ip4:203.0.113.10 -all"},
			"news.example.com":            {"v=spf1 ip4:203.0.113.10 -all"},
			"_dmarc.example.com":          {"v=DMARC1; p=none"},
			"mail._domainkey.example.com": {"v=DKIM1; p=AAAA"},
		},
		mx: map[string][]*net.MX{
			"example.com":      {{Host: "mx.example.com.", Pref: 10}},
			"news.example.com": {{Host: "mx.example.com.", Pref: 10}},
		},
	}
	results := Run(context.Background(), Options{Config: cfg, Resolver: r})
	var hit bool
	for _, res := range results {
		if res.Name == "spf_example.com" && res.Level == Fail {
			hit = true
			if !strings.Contains(res.Message, "2 SPF") {
				t.Fatalf("message=%s", res.Message)
			}
		}
	}
	if !hit {
		t.Fatal("expected dual SPF failure")
	}
}

func TestDKIMKeyMismatch(t *testing.T) {
	cfg := baseCfg()
	r := &fakeResolver{
		ips: map[string][]net.IPAddr{"mail.example.com": {{IP: net.ParseIP("203.0.113.10")}}},
		ptr: map[string][]string{"203.0.113.10": {"mail.example.com."}},
		txt: map[string][]string{
			"example.com":                 {"v=spf1 -all"},
			"mail.example.com":            {"v=spf1 -all"},
			"news.example.com":            {"v=spf1 -all"},
			"mail._domainkey.example.com": {"v=DKIM1; p=BBBB"},
			"_dmarc.example.com":          {"v=DMARC1; p=none"},
		},
		mx: map[string][]*net.MX{"example.com": {{Host: "mx.", Pref: 10}}, "news.example.com": {{Host: "mx.", Pref: 10}}},
	}
	results := Run(context.Background(), Options{
		Config: cfg, Resolver: r,
		DKIM: &DKIMKey{Selector: "mail", PublicKey: "AAAA"},
	})
	for _, res := range results {
		if res.Name == "dkim" && res.Level == Fail {
			return
		}
	}
	t.Fatal("expected dkim fail")
}

func TestEnvelopeImplicitMX(t *testing.T) {
	cfg := baseCfg()
	// only apex domain in senders
	cfg.Users = []config.User{{AllowedSenders: []string{"a@example.com"}, Enabled: true}}
	r := &fakeResolver{
		ips: map[string][]net.IPAddr{
			"mail.example.com": {{IP: net.ParseIP("203.0.113.10")}},
			"example.com":      {{IP: net.ParseIP("203.0.113.10")}},
		},
		ptr: map[string][]string{"203.0.113.10": {"mail.example.com."}},
		txt: map[string][]string{
			"example.com":                 {"v=spf1 -all"},
			"mail.example.com":            {"v=spf1 -all"},
			"mail._domainkey.example.com": {"v=DKIM1; p=A"},
			"_dmarc.example.com":          {"v=DMARC1; p=quarantine"},
		},
		mx: map[string][]*net.MX{}, // no MX
	}
	results := Run(context.Background(), Options{Config: cfg, Resolver: r})
	for _, res := range results {
		if res.Name == "envelope_mx_example.com" {
			if res.Level != Warn {
				t.Fatalf("level=%s msg=%s", res.Level, res.Message)
			}
			return
		}
	}
	t.Fatal("missing envelope mx check")
}

func TestNoPublicInternetInFake(t *testing.T) {
	// Ensure Run with empty fake produces deterministic failures without panic
	// and without dialing the network (fake returns empty).
	cfg := baseCfg()
	r := &fakeResolver{
		ips: map[string][]net.IPAddr{},
		ptr: map[string][]string{},
		txt: map[string][]string{},
		mx:  map[string][]*net.MX{},
	}
	results := Run(context.Background(), Options{Config: cfg, Resolver: r})
	if len(results) == 0 {
		t.Fatal("expected results")
	}
	if !Failed(results) {
		t.Fatal("expected failures with empty DNS")
	}
}
