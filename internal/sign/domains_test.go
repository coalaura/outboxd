package sign

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/coalaura/outboxd/internal/config"
	"github.com/emersion/go-msgauth/dkim"
)

func TestIndependentDomainSignatures(t *testing.T) {
	cfg := config.Default()

	cfg.Server.DataDirectory = t.TempDir()
	cfg.Domains[0].Name = "example.com"
	cfg.Domains = append(cfg.Domains, config.Domain{Name: "example.net", DKIM: config.DKIM{Selector: "other", PrivateKeyFile: "dkim/net.key", Headers: cfg.Domains[0].DKIM.Headers}})
	cfg.Domains = append(cfg.Domains, config.Domain{Name: "news.example.com", DKIM: config.DKIM{Selector: "news", PrivateKeyFile: "dkim/news.key", Headers: cfg.Domains[0].DKIM.Headers}})

	signers, created, err := Ensure(cfg)
	if err != nil || !created {
		t.Fatalf("Ensure: created=%v err=%v", created, err)
	}

	records := signers.Records()
	if records["example.com"] == records["example.net"] || records["example.com"] == records["news.example.com"] {
		t.Fatal("domains share DKIM keys")
	}

	loaded, created, err := Ensure(cfg)
	if err != nil || created {
		t.Fatalf("Ensure existing: created=%v err=%v", created, err)
	}

	for domain, record := range loaded.Records() {
		if records[domain] != record {
			t.Fatalf("provision replaced %s key", domain)
		}
	}

	cases := map[string]string{
		"Alice@EXAMPLE.COM":           "example.com",
		"alice@example.net":           "example.net",
		"alice@news.example.com":      "news.example.com",
		"alice@deep.news.example.com": "news.example.com",
		"alice@other.example.com":     "example.com",
	}

	for from, want := range cases {
		t.Run(from, func(t *testing.T) {
			t.Parallel()

			message := "From: " + from + "\r\nTo: recipient@example.org\r\nSubject: independent signing\r\n\r\nbody\r\n"

			signature, err := loaded.Signature(from, []byte(message))
			if err != nil {
				t.Fatal(err)
			}

			verified, err := dkim.VerifyWithOptions(strings.NewReader(signature+message), &dkim.VerifyOptions{
				LookupTXT: func(query string) ([]string, error) {
					domain := cfg.DomainFor(want)
					if query != domain.DKIM.Selector+"._domainkey."+want {
						t.Fatalf("wrong DKIM lookup: %s", query)
					}

					return []string{records[want]}, nil
				},
			})

			if err != nil || len(verified) != 1 || verified[0].Err != nil || verified[0].Domain != want {
				t.Fatalf("verification: %+v, %v", verified, err)
			}
		})
	}

	_, err = loaded.Signature("attacker@badexample.com", []byte("From: attacker@badexample.com\r\n\r\nbody\r\n"))
	if err == nil {
		t.Fatal("signed unknown domain")
	}
}

func TestAdditionalDomainRequiresIndependentProvisionedKey(t *testing.T) {
	cfg := config.Default()

	cfg.Server.DataDirectory = t.TempDir()

	_, _, err := Ensure(cfg)
	if err != nil {
		t.Fatal(err)
	}

	cfg.Domains = append(cfg.Domains, config.Domain{Name: "example.net", DKIM: config.DKIM{Selector: "other", PrivateKeyFile: "dkim/net.key", Headers: cfg.Domains[0].DKIM.Headers}})

	_, err = Load(cfg)
	if err == nil {
		t.Fatal("loaded unprovisioned domain")
	}

	path := filepath.Join(cfg.Server.DataDirectory, "dkim/net.key")

	_, err = os.Stat(path)
	if !os.IsNotExist(err) {
		t.Fatalf("Load created key: %v", err)
	}

	key, err := os.ReadFile(filepath.Join(cfg.Server.DataDirectory, cfg.Domains[0].DKIM.PrivateKeyFile))
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile(path, key, 0600)
	if err != nil {
		t.Fatal(err)
	}

	_, err = Load(cfg)
	if err == nil || !strings.Contains(err.Error(), "distinct keys") {
		t.Fatalf("shared key: %v", err)
	}
}
