package deliver

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/coalaura/outboxd/internal/config"
	"github.com/coalaura/outboxd/internal/disk"
	"github.com/coalaura/outboxd/internal/queue"
)

type limitedDSNReader struct {
	*bytes.Reader
	read   int
	closed bool
}

func (r *limitedDSNReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	r.read += n
	return n, err
}

func (r *limitedDSNReader) Close() error {
	r.closed = true
	return nil
}

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
	err = json.Unmarshal(raw, env)
	if err != nil {
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
	err = q.Add(env, []byte("body"))
	if err != nil {
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
	err = d.complete(got)
	if err != nil {
		t.Fatalf("complete returned cleanup warning: %v", err)
	}

	messages, bytes := q.Stats()
	if messages != 0 || bytes != 0 {
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
	err = q.Add(orig, body)
	if err != nil {
		t.Fatal(err)
	}

	err = d.ensureDSN(orig)
	if err != nil {
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

func TestEnsureDSNInheritsSMTPUTF8ForASCIIReport(t *testing.T) {
	dir := t.TempDir()
	q, err := queue.Open(dir, queue.Limits{})
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = q.Close() })
	d := New(&config.Config{Server: config.Server{Hostname: "mail.test"}}, q, nopLog{})
	now := time.Now()
	orig := &queue.Envelope{
		ID: "orig2", Username: "user", Sender: "alice@ex.com",
		Recipients: []queue.Recipient{{
			Address: "bob@ex.com", Domain: "ex.com",
			Status: queue.StatusFailed, Detail: "gone",
		}},
		Created: now, NextAttempt: now,
		SMTPUTF8: true,
	}
	err = q.Add(orig, []byte("From: x\r\nTo: y\r\nSubject: t\r\n\r\nHi\r\n"))
	if err != nil {
		t.Fatal(err)
	}

	err = d.ensureDSN(orig)
	if err != nil {
		t.Fatal(err)
	}

	env := loadReadyEnvelope(t, q.Path(), queue.DSNID(orig.ID, orig.Incarnation, orig.DSNGeneration))
	if !env.SMTPUTF8 {
		t.Fatal("DSN envelope must inherit source SMTPUTF8")
	}

	r, err := q.Reader(env.ID)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(msg, []byte("report-type=global-delivery-status")) {
		t.Fatal("SMTPUTF8 DSN envelope contains non-global report")
	}
}

func TestEnsureDSNFlagsFailedUTF8Recipient(t *testing.T) {
	dir := t.TempDir()
	q, err := queue.Open(dir, queue.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = q.Close() })
	d := New(&config.Config{Server: config.Server{Hostname: "mail.test"}}, q, nopLog{})
	now := time.Now()
	orig := &queue.Envelope{
		ID: "orig-utf8-failed", Username: "user", Sender: "alice@ex.com",
		Recipients: []queue.Recipient{{
			Address: "björn@ex.com", Domain: "ex.com", Status: queue.StatusFailed, Detail: "gone",
		}},
		Created: now, NextAttempt: now, SMTPUTF8: true,
	}
	if err := q.Add(orig, []byte("From: x\r\nTo: y\r\n\r\nHi\r\n")); err != nil {
		t.Fatal(err)
	}
	if err := d.ensureDSN(orig); err != nil {
		t.Fatal(err)
	}

	env := loadReadyEnvelope(t, q.Path(), queue.DSNID(orig.ID, orig.Incarnation, orig.DSNGeneration))
	if !env.SMTPUTF8 {
		t.Fatal("failed UTF-8 recipient in report must set SMTPUTF8")
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
	err = q.Add(orig, []byte("From: a\r\nTo: b\r\nSubject: t\r\n\r\nHi\r\n"))
	if err != nil {
		t.Fatal(err)
	}

	err = d.ensureDSN(orig)
	if err != nil {
		t.Fatal(err)
	}

	env := loadReadyEnvelope(t, q.Path(), queue.DSNID(orig.ID, orig.Incarnation, orig.DSNGeneration))
	if !env.EightBit {
		t.Fatal("high-bit DSN content must set EightBit")
	}
}

func TestReadDSNOriginalBounded(t *testing.T) {
	header := "From: alice@example.com\r\nSubject: original\r\n\r\n"
	source := header + strings.Repeat("x", 2<<20)
	r := &limitedDSNReader{Reader: bytes.NewReader([]byte(source))}
	original, err := readDSNOriginal(r)
	if err != nil {
		t.Fatal(err)
	}

	if r.read > dsnOriginalLimit+1 {
		t.Fatalf("read=%d exceeds bound=%d", r.read, dsnOriginalLimit+1)
	}

	if !r.closed {
		t.Fatal("original reader was not closed")
	}

	if string(original) != header {
		t.Fatalf("retained original=%q", original)
	}
}

func TestReadDSNOriginalCapsMissingHeaderTerminator(t *testing.T) {
	r := &limitedDSNReader{Reader: bytes.NewReader(bytes.Repeat([]byte("x"), dsnOriginalLimit*2))}
	original, err := readDSNOriginal(r)
	if err != nil {
		t.Fatal(err)
	}

	if len(original) != dsnOriginalLimit || r.read != dsnOriginalLimit+1 {
		t.Fatalf("retained=%d read=%d", len(original), r.read)
	}

	if !r.closed {
		t.Fatal("original reader was not closed")
	}
}

func TestBuildDSNUsesEnhancedStatusAndFallback(t *testing.T) {
	created := time.Date(2025, 2, 3, 4, 5, 6, 0, time.FixedZone("test", -7*60*60))
	env := &queue.Envelope{
		ID: "status-dsn", Sender: "alice@example.com",
		Created: created,
		Recipients: []queue.Recipient{
			{Address: "enhanced@example.com", Status: queue.StatusFailed, Code: 550, EnhancedCode: "5.1.1", Detail: "550 5.1.1 missing"},
			{Address: "basic@example.com", Status: queue.StatusFailed, Code: 554, Detail: "554 rejected"},
			{Address: "unknown@example.com", Status: queue.StatusFailed, Detail: "failed"},
		},
	}
	msg, err := buildDSN("mail.test", env, nil)
	if err != nil {
		t.Fatal(err)
	}

	for _, status := range []string{"Status: 5.1.1\r\n", "Status: 5.0.0\r\n"} {

		if !bytes.Contains(msg, []byte(status)) {
			t.Fatalf("missing %q in DSN", status)
		}
	}

	if !bytes.Contains(msg, []byte("Arrival-Date: "+created.UTC().Format(time.RFC1123Z)+"\r\n")) {
		t.Fatal("DSN Arrival-Date does not use envelope creation time")
	}
	for _, form := range []string{
		"report-type=delivery-status", "Content-Type: message/delivery-status", "Final-Recipient: rfc822;", "Content-Type: message/rfc822",
	} {
		if !bytes.Contains(msg, []byte(form)) {
			t.Fatalf("ASCII DSN missing RFC 3464 form %q", form)
		}
	}
}

func TestBuildDSNUsesRFC6533GlobalForms(t *testing.T) {
	env := &queue.Envelope{
		ID: "global-dsn", Sender: "alice@example.com", Created: time.Now(), SMTPUTF8: true,
		Recipients: []queue.Recipient{{
			Address: "bob@example.com", Status: queue.StatusFailed, Detail: "5.1.1 unknown recipient",
		}},
	}
	msg, err := buildDSN("mail.test", env, []byte("From: alice@example.com\r\n\r\nbody\r\n"))
	if err != nil {
		t.Fatal(err)
	}

	for _, form := range []string{
		"report-type=global-delivery-status", "Content-Type: message/global-delivery-status", "Final-Recipient: utf-8; bob@example.com", "Content-Type: message/global",
	} {
		if !bytes.Contains(msg, []byte(form)) {
			t.Fatalf("SMTPUTF8 DSN missing RFC 6533 form %q", form)
		}
	}
	for _, asciiForm := range []string{"message/delivery-status", "Final-Recipient: rfc822;", "Content-Type: message/rfc822"} {
		if bytes.Contains(msg, []byte(asciiForm)) {
			t.Fatalf("SMTPUTF8 DSN retained RFC 3464 form %q", asciiForm)
		}
	}
}

func TestSanitizeHeaderPreservesValidUTF8AtLimit(t *testing.T) {
	in := strings.Repeat("a", 199) + "é"
	got := sanitizeHeader(in)
	if !utf8.ValidString(got) || len(got) > 200 {
		t.Fatalf("sanitizeHeader returned invalid boundary: %q", got)
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
	err = q.Add(source, []byte("From: a\r\nTo: b\r\n\r\nbody\r\n"))
	if err != nil {
		t.Fatal(err)
	}

	_, err = q.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	err = d.ensureDSN(source)
	if err != nil {
		t.Fatal(err)
	}

	dsn, err := q.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if dsn.ID != source.DSNID {
		t.Fatalf("scheduled DSN %s, source links %s", dsn.ID, source.DSNID)
	}

	err = q.Finish(dsn)
	if err != nil {
		t.Fatal(err)
	}

	err = q.Close()
	if err != nil {
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

	err = d.ensureDSN(recovered)
	if err != nil {
		t.Fatal(err)
	}

	if q.Len() != 0 {
		t.Fatalf("completed DSN was regenerated; Len=%d", q.Len())
	}
}
