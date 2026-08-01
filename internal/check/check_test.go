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

func TestSPFEffectivePolicyMismatchFails(t *testing.T) {
	cfg := baseCfg()
	cfg.Users = nil
	r := &fakeResolver{txt: map[string][]string{
		"example.com":      {"v=spf1 ip4:198.51.100.1 -all"},
		"mail.example.com": {cfg.ExpectedSPF()},
	}}
	results := checkSPF(context.Background(), r, cfg)
	for _, result := range results {
		if result.Name == "spf_example.com" && result.Level == Fail && strings.Contains(result.Message, "does not match") {
			return
		}
	}
	t.Fatal("expected effective SPF mismatch failure")
}

func TestSPFVersionMustBeExactFirstToken(t *testing.T) {
	cfg := baseCfg()
	cfg.Users = nil
	r := &fakeResolver{txt: map[string][]string{
		"example.com":      {"v=spf10 " + strings.TrimPrefix(cfg.ExpectedSPF(), "v=spf1 ")},
		"mail.example.com": {cfg.ExpectedSPF()},
	}}
	for _, result := range checkSPF(context.Background(), r, cfg) {
		if result.Name == "spf_example.com" && result.Level == Fail && strings.Contains(result.Message, "no SPF") {
			return
		}
	}
	t.Fatal("SPF version prefix was accepted")
}

func TestDMARCStrictTagParsing(t *testing.T) {
	cfg := baseCfg()
	tests := []struct {
		name   string
		record string
	}{
		{"version prefix", "v=DMARC10; p=none"},
		{"version not first", "p=none; v=DMARC1"},
		{"duplicate policy", "v=DMARC1; p=none; p=reject"},
		{"malformed tag", "v=DMARC1; broken; p=none"},
		{"invalid policy", "v=DMARC1; p=invalid"},
		{"invalid rua", "v=DMARC1; p=none; rua=mailto:a@example.com!10x"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := &fakeResolver{txt: map[string][]string{"_dmarc.example.com": {test.record}}}
			results := checkDMARC(context.Background(), r, cfg)
			if len(results) != 1 || results[0].Level != Fail {
				t.Fatalf("record %q accepted: %+v", test.record, results)
			}
		})
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

func TestDuplicateDKIMFails(t *testing.T) {
	cfg := baseCfg()
	r := &fakeResolver{txt: map[string][]string{
		"mail._domainkey.example.com": {"v=DKIM1; p=AAAA", "v=DKIM1; p=BBBB"},
	}}
	result := checkDKIM(context.Background(), r, cfg, nil)[0]
	if result.Level != Fail {
		t.Fatalf("duplicate DKIM level=%s", result.Level)
	}
}

func TestDMARCConfiguredPolicyMismatchFails(t *testing.T) {
	cfg := baseCfg()
	for _, test := range []struct {
		policy string
		level  Level
	}{
		{"none", Warn},
		{"reject", Fail},
	} {
		r := &fakeResolver{txt: map[string][]string{
			"_dmarc.example.com": {"v=DMARC1; p=" + test.policy + "; rua=mailto:dmarc@reports.example.net"},
		}}
		result := checkDMARC(context.Background(), r, cfg)[0]
		if result.Level != test.level {
			t.Fatalf("published p=%s level=%s want %s: %s", test.policy, result.Level, test.level, result.Message)
		}
	}
}

func TestNullMXFailsWithoutImplicitFallback(t *testing.T) {
	cfg := baseCfg()
	cfg.Users = nil
	for _, mxs := range [][]*net.MX{
		{{Host: ".", Pref: 0}},
		{{Host: ".", Pref: 0}, {Host: "mx.example.com.", Pref: 10}},
	} {
		r := &fakeResolver{
			mx:  map[string][]*net.MX{"example.com": mxs},
			ips: map[string][]net.IPAddr{"example.com": {{IP: net.ParseIP("203.0.113.10")}}},
		}
		result := checkEnvelopeMX(context.Background(), r, cfg)[0]
		if result.Level != Fail || !strings.Contains(result.Message, "null MX") {
			t.Fatalf("null MX accepted: %+v", result)
		}
	}
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
