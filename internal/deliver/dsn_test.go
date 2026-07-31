package deliver

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/coalaura/outboxd/internal/config"
	"github.com/coalaura/outboxd/internal/disk"
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

func TestCompleteIgnoresDeferredTrashCleanup(t *testing.T) {
	disk.SetHooks(disk.Hooks{})
	t.Cleanup(func() { disk.SetHooks(disk.Hooks{}) })
	q, err := queue.Open(t.TempDir(), queue.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = q.Close() })
	now := time.Now()
	env := &queue.Envelope{
		ID:       "cleanup-warning",
		Username: "user",
		Sender:   "sender@example.test",
		Recipients: []queue.Recipient{{
			Address: "recipient@example.test",
			Domain:  "example.test",
			Status:  queue.StatusPending,
		}},
		Created:     now,
		NextAttempt: now,
	}
	if err := q.Add(env, []byte("body")); err != nil {
		t.Fatal(err)
	}
	got, err := q.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got.Recipients[0].Status = queue.StatusSent
	disk.SetHooks(disk.Hooks{BeforeRemoveAll: func(string) error {
		return os.ErrPermission
	}})
	d := New(&config.Config{Server: config.Server{Hostname: "mail.test"}}, q, nopLog{})
	if err := d.complete(got); err != nil {
		t.Fatalf("complete returned cleanup warning: %v", err)
	}
	if messages, bytes := q.Stats(); messages != 0 || bytes != 0 {
		t.Fatalf("Stats=(%d, %d) want (0, 0)", messages, bytes)
	}
}

func TestEnsureDSNFlagsASCII(t *testing.T) {
	dir := t.TempDir()
	q, err := queue.Open(dir, queue.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = q.Close() })
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
	if orig.DSNID == "" {
		t.Fatal("DSNID")
	}
	env := loadReadyEnvelope(t, q.Path(), queue.DSNID(orig.ID, orig.Incarnation, orig.DSNGeneration))
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
	t.Cleanup(func() { _ = q.Close() })
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
	env := loadReadyEnvelope(t, q.Path(), queue.DSNID(orig.ID, orig.Incarnation, orig.DSNGeneration))
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
	t.Cleanup(func() { _ = q.Close() })
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
	env := loadReadyEnvelope(t, q.Path(), queue.DSNID(orig.ID, orig.Incarnation, orig.DSNGeneration))
	if !env.EightBit {
		t.Fatal("high-bit DSN content must set EightBit")
	}
}

func TestCompletedDSNDoesNotRegenerateBeforeSourceTransition(t *testing.T) {
	root := t.TempDir()
	q, err := queue.Open(root, queue.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	d := New(&config.Config{Server: config.Server{Hostname: "mail.test"}}, q, nopLog{})
	now := time.Now()
	source := &queue.Envelope{
		ID: "dsn-source-crash", Username: "user", Sender: "alice@ex.com",
		Recipients: []queue.Recipient{{
			Address: "bob@ex.com", Domain: "ex.com",
			Status: queue.StatusFailed, Detail: "gone",
		}},
		Created: now, NextAttempt: now,
	}
	if err := q.Add(source, []byte("From: a\r\nTo: b\r\n\r\nbody\r\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Next(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := d.ensureDSN(source); err != nil {
		t.Fatal(err)
	}
	dsn, err := q.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if dsn.ID != source.DSNID {
		t.Fatalf("scheduled DSN %s, source links %s", dsn.ID, source.DSNID)
	}
	if err := q.Finish(dsn); err != nil {
		t.Fatal(err)
	}
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}

	q, err = queue.Open(root, queue.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = q.Close() })
	d = New(&config.Config{Server: config.Server{Hostname: "mail.test"}}, q, nopLog{})
	recovered, err := q.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if recovered.ID != source.ID || recovered.DSNID == "" {
		t.Fatalf("recovered source lost DSN link: %#v", recovered)
	}
	if err := d.ensureDSN(recovered); err != nil {
		t.Fatal(err)
	}
	if q.Len() != 0 {
		t.Fatalf("completed DSN was regenerated; Len=%d", q.Len())
	}
}
