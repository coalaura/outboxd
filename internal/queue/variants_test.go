package queue

import (
	"bytes"
	"errors"
	"io"
	"path/filepath"
	"testing"
)

func TestMessageBodyVariantsAreReadIndependently(t *testing.T) {
	q := mustOpen(t, t.TempDir(), Limits{})

	first := []byte("From: a@example.com\r\n\r\nfirst\r\n")
	second := []byte("From: a@example.com\r\n\r\nsecond\r\n")

	body := append(append([]byte(nil), first...), second...)

	envelope := testEnv("variants")

	envelope.Recipients = []Recipient{
		{Address: "one@example.com", Domain: "example.com", Status: StatusPending},
		{Address: "two@example.com", Domain: "example.com", Body: 1, Status: StatusPending},
	}

	envelope.Bodies = []Body{
		NewBody(0, first, false),
		NewBody(int64(len(first)), second, false),
	}

	err := q.Add(envelope, body)
	if err != nil {
		t.Fatal(err)
	}

	for index, want := range [][]byte{first, second} {
		reader, err := q.ReaderVariant(envelope.ID, index)
		if err != nil {
			t.Fatal(err)
		}

		got, err := io.ReadAll(reader)
		closeErr := reader.Close()

		if err != nil || closeErr != nil {
			t.Fatalf("read variant %d: read %v, close %v", index, err, closeErr)
		}

		if string(got) != string(want) {
			t.Fatalf("variant %d = %q, want %q", index, got, want)
		}
	}

	got, err := q.ReadBody(envelope.ID)
	if err != nil {
		t.Fatal(err)
	}

	if string(got) != string(first) {
		t.Fatalf("ReadBody() = %q, want first variant", got)
	}

	var exported bytes.Buffer

	err = q.ExportReady(envelope.ID, &exported)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(exported.Bytes(), first) {
		t.Fatalf("ExportReady() = %q, want first variant", exported.Bytes())
	}

	loaded, err := q.LoadReady(envelope.ID)
	if err != nil {
		t.Fatal(err)
	}

	loaded.Recipients[0].Body = 1
	loaded.Recipients[1].Body = 0

	err = q.Retry(loaded)
	if !errors.Is(err, ErrIDConflict) {
		t.Fatalf("Retry() after body reassignment error = %v, want ErrIDConflict", err)
	}
}

func TestAddRejectsVariantDigestMismatch(t *testing.T) {
	q := mustOpen(t, t.TempDir(), Limits{})

	envelope := testEnv("bad-variant")
	envelope.Bodies = []Body{NewBody(0, []byte("wrong"), false)}

	err := q.Add(envelope, []byte("actual"))
	if err == nil {
		t.Fatal("Add() accepted mismatched variant digest")
	}
}

func TestAddDSNRejectsVariantDigestMismatch(t *testing.T) {
	q := mustOpen(t, t.TempDir(), Limits{})

	source := testEnv("dsn-bad-variant-source")

	err := q.Add(source, []byte("source"))
	if err != nil {
		t.Fatal(err)
	}

	dsn := testDSN(source)

	dsn.Bodies = []Body{NewBody(0, []byte("bad"), false)}

	err = q.AddDSN(source, dsn, []byte("dsn"))
	if err == nil {
		t.Fatal("AddDSN() accepted mismatched variant digest")
	}
}

func TestAddDSNRejectsSourceBodyReassignment(t *testing.T) {
	q := mustOpen(t, t.TempDir(), Limits{})

	first := []byte("first")
	second := []byte("second")

	body := append(append([]byte(nil), first...), second...)

	source := testEnv("dsn-body-reassignment-source")

	source.Recipients = []Recipient{
		{Address: "one@example.com", Domain: "example.com", Status: StatusPending},
		{Address: "two@example.com", Domain: "example.com", Body: 1, Status: StatusPending},
	}

	source.Bodies = []Body{
		NewBody(0, first, false),
		NewBody(int64(len(first)), second, false),
	}

	err := q.Add(source, body)
	if err != nil {
		t.Fatal(err)
	}

	source.Recipients[0].Body = 1
	source.Recipients[1].Body = 0

	err = q.AddDSN(source, testDSN(source), []byte("dsn"))
	if !errors.Is(err, ErrIDConflict) {
		t.Fatalf("AddDSN() after body reassignment error = %v, want ErrIDConflict", err)
	}
}

func TestRetryRejectsDSNLinkMutation(t *testing.T) {
	q := mustOpen(t, t.TempDir(), Limits{})

	source := testEnv("dsn-link-mutation-source")

	err := q.Add(source, []byte("source"))
	if err != nil {
		t.Fatal(err)
	}

	err = q.AddDSN(source, testDSN(source), []byte("dsn"))
	if err != nil {
		t.Fatal(err)
	}

	loaded, err := q.LoadReady(source.ID)
	if err != nil {
		t.Fatal(err)
	}

	loaded.DSNID = ""

	err = q.Retry(loaded)
	if !errors.Is(err, ErrIDConflict) {
		t.Fatalf("Retry() after DSN link mutation error = %v, want ErrIDConflict", err)
	}
}

func TestLoadRejectsPersistedVariantDigestMismatch(t *testing.T) {
	q := mustOpen(t, t.TempDir(), Limits{})

	first := []byte("first")
	second := []byte("second")

	body := append(append([]byte(nil), first...), second...)

	envelope := testEnv("persisted-bad-variant")

	envelope.Recipients = []Recipient{
		{Address: "one@example.com", Domain: "example.com", Status: StatusPending},
		{Address: "two@example.com", Domain: "example.com", Body: 1, Status: StatusPending},
	}

	envelope.Bodies = []Body{
		NewBody(0, first, false),
		NewBody(int64(len(first)), second, false),
	}

	err := q.Add(envelope, body)
	if err != nil {
		t.Fatal(err)
	}

	loaded, err := q.LoadReady(envelope.ID)
	if err != nil {
		t.Fatal(err)
	}

	loaded.Bodies[1].Digest = bodyDigest([]byte("not second"))

	err = q.writeMeta(filepath.Join(q.ready, envelope.ID, metaName), loaded)
	if err != nil {
		t.Fatal(err)
	}

	_, err = q.LoadReady(envelope.ID)
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("LoadReady() error = %v, want ErrCorrupt", err)
	}
}
