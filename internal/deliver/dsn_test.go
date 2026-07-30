package deliver

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/coalaura/outboxd/internal/config"
	"github.com/coalaura/outboxd/internal/queue"
)

type nopLog struct{}

func (nopLog) Printf(string, ...any) {}
func (nopLog) Println(...any)        {}

func loadReadyEnvelope(t *testing.T, root, id string) *queue.Envelope {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, "ready", id, "meta.json"))
	if err != nil {
		t.Fatal(err)
	}
	env := new(queue.Envelope)
	if err := json.Unmarshal(raw, env); err != nil {
		t.Fatal(err)
	}
	return env
}

func TestEnsureDSNFlagsASCII(t *testing.T) {
	dir := t.TempDir()
	q, err := queue.Open(dir, queue.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	d := New(&config.Config{Server: config.Server{Hostname: "mail.test", Domain: "test"}}, q, nopLog{})

	now := time.Now()
	orig := &queue.Envelope{
		ID: "orig1", Username: "user", Sender: "alice@ex.com",
		Recipients: []queue.Recipient{{
			Address: "bob@ex.com", Domain: "ex.com",
			Status: queue.StatusFailed, Detail: "permanent failure",
		}},
		Created: now, NextAttempt: now,
	}
	body := []byte("From: alice@ex.com\r\nTo: bob@ex.com\r\nSubject: t\r\n\r\nHi\r\n")
	if err := q.Add(orig, body); err != nil {
		t.Fatal(err)
	}
	if err := d.ensureDSN(orig); err != nil {
		t.Fatal(err)
	}
	if !orig.DSNSent {
		t.Fatal("DSNSent")
	}
	env := loadReadyEnvelope(t, q.Path(), "dsn.orig1")
	if env.SMTPUTF8 {
		t.Fatal("ASCII sender DSN SMTPUTF8 must be false")
	}
	if env.EightBit {
		t.Fatal("ASCII DSN body EightBit must be false")
	}
}

func TestEnsureDSNFlagsUTF8Recipient(t *testing.T) {
	dir := t.TempDir()
	q, err := queue.Open(dir, queue.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	d := New(&config.Config{Server: config.Server{Hostname: "mail.test"}}, q, nopLog{})
	now := time.Now()
	orig := &queue.Envelope{
		ID: "orig2", Username: "user", Sender: "björn@ex.com",
		Recipients: []queue.Recipient{{
			Address: "bob@ex.com", Domain: "ex.com",
			Status: queue.StatusFailed, Detail: "gone",
		}},
		Created: now, NextAttempt: now,
		SMTPUTF8: true,
	}
	if err := q.Add(orig, []byte("From: x\r\nTo: y\r\nSubject: t\r\n\r\nHi\r\n")); err != nil {
		t.Fatal(err)
	}
	if err := d.ensureDSN(orig); err != nil {
		t.Fatal(err)
	}
	env := loadReadyEnvelope(t, q.Path(), "dsn.orig2")
	if !env.SMTPUTF8 {
		t.Fatal("UTF-8 DSN recipient must set SMTPUTF8")
	}
}

func TestEnsureDSNEightBitFromHighOctets(t *testing.T) {
	dir := t.TempDir()
	q, err := queue.Open(dir, queue.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	d := New(&config.Config{Server: config.Server{Hostname: "mail.test"}}, q, nopLog{})
	now := time.Now()
	orig := &queue.Envelope{
		ID: "orig3", Username: "user", Sender: "alice@ex.com",
		Recipients: []queue.Recipient{{
			Address: "bob@ex.com", Domain: "ex.com",
			Status: queue.StatusFailed, Detail: "caf\xc3\xa9 failed",
		}},
		Created: now, NextAttempt: now,
	}
	if err := q.Add(orig, []byte("From: a\r\nTo: b\r\nSubject: t\r\n\r\nHi\r\n")); err != nil {
		t.Fatal(err)
	}
	if err := d.ensureDSN(orig); err != nil {
		t.Fatal(err)
	}
	env := loadReadyEnvelope(t, q.Path(), "dsn.orig3")
	if !env.EightBit {
		t.Fatal("high-bit DSN content must set EightBit")
	}
}
