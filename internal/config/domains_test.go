package config

import (
	"path/filepath"
	"strings"
	"testing"
)

type domainValidationCase struct {
	name   string
	change func(*Config)
	want   string
}

func TestMultipleDomains(t *testing.T) {
	cfg := Default()

	cfg.Server.DataDirectory = t.TempDir()
	cfg.Domains[0].Name = " Example.COM. "
	cfg.Domains = append(cfg.Domains, Domain{Name: "News.Example.COM", DKIM: DKIM{Selector: "NEWS", PrivateKeyFile: "dkim/news.key"}})
	cfg.Domains = append(cfg.Domains, Domain{Name: "example.net", DKIM: DKIM{PrivateKeyFile: "dkim/net.key"}})

	cfg.applyDefaults()

	err := cfg.Init()
	if err != nil {
		t.Fatal(err)
	}

	queries := map[string]string{
		"EXAMPLE.COM.":             "example.com",
		"other.example.com":        "example.com",
		"news.example.com":         "news.example.com",
		"deep.news.example.com":    "news.example.com",
		"example.net":              "example.net",
		"badexample.com":           "",
		"example.com.attacker.net": "",
	}

	for query, want := range queries {
		matched := cfg.DomainFor(query)

		if want == "" {
			if matched != nil {
				t.Fatalf("DomainFor(%q) = %q", query, matched.Name)
			}

			continue
		}

		if matched == nil || matched.Name != want {
			t.Fatalf("DomainFor(%q) = %+v, want %q", query, matched, want)
		}
	}

	path := filepath.Join(t.TempDir(), "config.yml")
	cfg.path = path

	err = cfg.Save()
	if err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	if len(loaded.Domains) != 3 || loaded.Domains[1].DKIM.Selector != "news" || loaded.Domains[2].DKIM.Selector != "mail" {
		t.Fatalf("domain round trip: %+v", loaded.Domains)
	}
}

func TestInvalidDomains(t *testing.T) {
	cases := []domainValidationCase{
		{
			name: "empty",
			change: func(cfg *Config) {
				cfg.Domains = nil
			},
			want: "domains must contain",
		},
		{
			name: "duplicate",
			change: func(cfg *Config) {
				cfg.Domains[1].Name = cfg.Domains[0].Name
			},
			want: "duplicate domain",
		},
		{
			name: "shared path",
			change: func(cfg *Config) {
				cfg.Domains[1].DKIM.PrivateKeyFile = cfg.Domains[0].DKIM.PrivateKeyFile
			},
			want: "distinct key paths",
		},
		{
			name: "escaped path",
			change: func(cfg *Config) {
				cfg.Domains[1].DKIM.PrivateKeyFile = "../outside.key"
			},
			want: "private_key_file",
		},
		{
			name: "missing key",
			change: func(cfg *Config) {
				cfg.Domains[1].DKIM.PrivateKeyFile = ""
			},
			want: "private_key_file must not be empty",
		},
		{
			name: "missing From",
			change: func(cfg *Config) {
				cfg.Domains[1].DKIM.Headers = []string{"Sender"}
			},
			want: "must contain From",
		},
		{
			name: "duplicate header",
			change: func(cfg *Config) {
				cfg.Domains[1].DKIM.Headers = []string{"From", "Sender", "from"}
			},
			want: "duplicate",
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			cfg := Default()

			cfg.Server.DataDirectory = t.TempDir()
			cfg.Domains = append(cfg.Domains, Domain{Name: "example.net", DKIM: DKIM{Selector: "mail", PrivateKeyFile: "dkim/net.key", Headers: defaultDKIMHeaders()}})

			test.change(cfg)

			err := cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Validate() = %v, want %q", err, test.want)
			}
		})
	}
}

func TestAutocryptUsesMostSpecificDomain(t *testing.T) {
	cfg := Default()

	cfg.Server.DataDirectory = t.TempDir()
	cfg.Domains[0].Name = "example.com"

	cfg.Domains = append(cfg.Domains, Domain{
		Name: "news.example.com",
		DKIM: DKIM{
			Selector:       "news",
			PrivateKeyFile: "dkim/news.key",
			Headers:        []string{"From", "Sender"},
		},
	})

	cfg.OpenPGP.Identities = []OpenPGPIdentity{{Sender: "alice@deep.news.example.com", SigningKey: "openpgp/alice.asc", Signing: "required", Autocrypt: true}}

	err := cfg.Init()
	if err == nil || !strings.Contains(err.Error(), "requires Autocrypt in the signing domain's dkim.headers") {
		t.Fatalf("Init() = %v, want missing Autocrypt coverage for child domain", err)
	}

	cfg.Domains[1].DKIM.Headers = append(cfg.Domains[1].DKIM.Headers, "Autocrypt")

	err = cfg.Init()
	if err != nil {
		t.Fatalf("Init() with child domain coverage: %v", err)
	}

	cfg.OpenPGP.Identities[0].Sender = "alice@unconfigured.example"

	err = cfg.Init()
	if err == nil || !strings.Contains(err.Error(), "outside configured domains") {
		t.Fatalf("Init() = %v, want unconfigured OpenPGP domain rejection", err)
	}
}
