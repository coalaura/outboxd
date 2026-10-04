package smtpd

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/coalaura/outboxd/internal/config"
	"github.com/coalaura/outboxd/internal/sign"
	"github.com/emersion/go-msgauth/dkim"
)

func TestSubmissionSelectsHeaderFromDomain(t *testing.T) {
	srv, cfg, spool, _, pool := testServerWithUser(t, originatorPassword)

	cfg.Domains = append(cfg.Domains, config.Domain{Name: "second.example", DKIM: config.DKIM{Selector: "second", PrivateKeyFile: "dkim/second.key", Headers: cfg.Domains[0].DKIM.Headers}})
	cfg.Users[0].AllowedSenders = append(cfg.Users[0].AllowedSenders, "alice@second.example")

	err := cfg.Init()
	if err != nil {
		t.Fatal(err)
	}

	signers, _, err := sign.Ensure(cfg)
	if err != nil {
		t.Fatal(err)
	}

	srv.signer = signers

	records := signers.Records()

	runTestSubmission(t, srv)

	client := dialSTARTTLS(t, srv.starttls.Addr, pool)
	defer client.close()

	client.authPlain(t, "alice", originatorPassword)

	client.cmd(t, "MAIL FROM:<other@second.example>", 550)
	client.cmd(t, "MAIL FROM:<alice@unconfigured.example>", 550)

	client.cmd(t, "MAIL FROM:<Alice.Sender@test.example>", 250)
	client.cmd(t, "RCPT TO:<dest@example.com>", 250)
	client.cmd(t, "DATA", 354)

	_, _ = io.WriteString(client.conn, "From: other@second.example\r\nTo: dest@example.com\r\n\r\nbody\r\n.\r\n")

	client.readCode(t, 550)

	client.cmd(t, "MAIL FROM:<Alice.Sender@test.example>", 250)
	client.cmd(t, "RCPT TO:<dest@example.com>", 250)
	client.cmd(t, "DATA", 354)

	_, _ = io.WriteString(client.conn, "From: alice@second.example\r\nSender: other@second.example\r\nTo: dest@example.com\r\n\r\nbody\r\n.\r\n")

	client.readCode(t, 550)

	client.cmd(t, "MAIL FROM:<Alice.Sender@test.example>", 250)
	client.cmd(t, "RCPT TO:<dest@example.com>", 250)
	client.cmd(t, "DATA", 354)

	_, _ = io.WriteString(client.conn, "From: alice@second.example\r\nSender: Alice.Sender@test.example\r\nTo: dest@example.com\r\nSubject: domain selection\r\n\r\nbody\r\n.\r\n")

	client.readCode(t, 250)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	envelope, err := spool.Next(ctx)
	if err != nil {
		t.Fatal(err)
	}

	if envelope.Sender != "Alice.Sender@test.example" {
		t.Fatalf("envelope sender: %s", envelope.Sender)
	}

	reader, err := spool.Reader(envelope.ID)
	if err != nil {
		t.Fatal(err)
	}

	defer reader.Close()

	verified, err := dkim.VerifyWithOptions(reader, &dkim.VerifyOptions{
		LookupTXT: func(query string) ([]string, error) {
			if query != "second._domainkey.second.example" {
				t.Fatalf("DKIM selected envelope/Sender identity: %s", query)
			}

			return []string{records["second.example"]}, nil
		},
	})

	if err != nil || len(verified) != 1 || verified[0].Err != nil || verified[0].Domain != "second.example" {
		t.Fatalf("verification: %+v, %v", verified, err)
	}
}
