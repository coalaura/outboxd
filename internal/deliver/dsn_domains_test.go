package deliver

import (
	"bytes"
	"io"
	"testing"
	"time"

	"github.com/coalaura/outboxd/internal/config"
	"github.com/coalaura/outboxd/internal/queue"
	"github.com/coalaura/outboxd/internal/sign"
	"github.com/emersion/go-msgauth/dkim"
)

func TestDSNSignsOriginalEnvelopeDomain(t *testing.T) {
	cfg := config.Default()

	cfg.Server.DataDirectory = t.TempDir()
	cfg.Server.Hostname = "mail.example.com"
	cfg.Domains[0].Name = "example.com"
	cfg.Domains = append(cfg.Domains, config.Domain{Name: "example.net", DKIM: config.DKIM{Selector: "other", PrivateKeyFile: "dkim/net.key", Headers: cfg.Domains[0].DKIM.Headers}})

	signers, _, err := sign.Ensure(cfg)
	if err != nil {
		t.Fatal(err)
	}

	spool, err := queue.Open(t.TempDir(), queue.Limits{})
	if err != nil {
		t.Fatal(err)
	}

	defer spool.Close()

	deliverer := New(cfg, spool, nopLog{})

	deliverer.signer = signers

	now := time.Now()

	source := &queue.Envelope{
		ID:          "domain-bounce",
		Username:    "alice",
		Sender:      "alice@example.net",
		Recipients:  []queue.Recipient{{Address: "missing@example.org", Domain: "example.org", Status: queue.StatusFailed, Detail: "gone"}},
		Created:     now,
		NextAttempt: now,
	}

	err = spool.Add(source, []byte("From: alice@example.com\r\nTo: missing@example.org\r\n\r\nbody\r\n"))
	if err != nil {
		t.Fatal(err)
	}

	err = deliverer.ensureDSN(source)
	if err != nil {
		t.Fatal(err)
	}

	envelope := loadReadyEnvelope(t, spool.Path(), source.DSNID)
	if envelope.Sender != "" || len(envelope.Recipients) != 1 || envelope.Recipients[0].Address != source.Sender {
		t.Fatalf("DSN envelope: %+v", envelope)
	}

	reader, err := spool.Reader(envelope.ID)
	if err != nil {
		t.Fatal(err)
	}

	defer reader.Close()

	message, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Contains(message, []byte("From: Mail Delivery System <MAILER-DAEMON@example.net>\r\n")) {
		t.Fatalf("DSN From identity: %s", message)
	}

	records := signers.Records()

	verified, err := dkim.VerifyWithOptions(bytes.NewReader(message), &dkim.VerifyOptions{
		LookupTXT: func(query string) ([]string, error) {
			if query != "other._domainkey.example.net" {
				t.Fatalf("wrong bounce identity: %s", query)
			}

			return []string{records["example.net"]}, nil
		},
	})

	if err != nil || len(verified) != 1 || verified[0].Err != nil || verified[0].Domain != "example.net" {
		t.Fatalf("DSN verification: %+v, %v", verified, err)
	}
}
