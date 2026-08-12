package main

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

type errReader struct{ err error }

func (e errReader) Read([]byte) (int, error) {
	return 0, e.err
}

func TestReadPasswordEmpty(t *testing.T) {
	_, err := readPassword(strings.NewReader(""), 1024)
	if err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("err=%v", err)
	}
}

func TestReadPasswordLFOnly(t *testing.T) {
	_, err := readPassword(strings.NewReader("\n"), 1024)
	if err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("err=%v", err)
	}
}

func TestReadPasswordCRLFOnly(t *testing.T) {
	_, err := readPassword(strings.NewReader("\r\n"), 1024)
	if err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("err=%v", err)
	}
}

func TestReadPasswordNoNewline(t *testing.T) {
	got, err := readPassword(strings.NewReader("s3cret-secure"), 1024)
	if err != nil {
		t.Fatal(err)
	}

	if got != "s3cret-secure" {
		t.Fatalf("got %q", got)
	}
}

func TestReadPasswordNormalLF(t *testing.T) {
	got, err := readPassword(strings.NewReader("s3cret-secure\n"), 1024)
	if err != nil {
		t.Fatal(err)
	}

	if got != "s3cret-secure" {
		t.Fatalf("got %q", got)
	}
}

func TestReadPasswordCRLF(t *testing.T) {
	got, err := readPassword(strings.NewReader("s3cret-secure\r\n"), 1024)
	if err != nil {
		t.Fatal(err)
	}

	if got != "s3cret-secure" {
		t.Fatalf("got %q", got)
	}
}

func TestReadPasswordExactMax(t *testing.T) {
	const max = 16

	pw := strings.Repeat("a", max)

	got, err := readPassword(strings.NewReader(pw), max)
	if err != nil {
		t.Fatal(err)
	}

	if got != pw {
		t.Fatal("max length not accepted")
	}
}

func TestReadPasswordExactMaxLF(t *testing.T) {
	const max = 16

	pw := strings.Repeat("a", max)

	got, err := readPassword(strings.NewReader(pw+"\n"), max)
	if err != nil {
		t.Fatal(err)
	}

	if got != pw {
		t.Fatalf("got %q", got)
	}
}

func TestReadPasswordExactMaxCRLF(t *testing.T) {
	const max = 16

	pw := strings.Repeat("a", max)

	got, err := readPassword(strings.NewReader(pw+"\r\n"), max)
	if err != nil {
		t.Fatal(err)
	}

	if got != pw {
		t.Fatalf("got %q", got)
	}
}

func TestReadPasswordMaxPlusOne(t *testing.T) {
	const max = 16

	pw := strings.Repeat("a", max+1)

	_, err := readPassword(strings.NewReader(pw), max)
	if err == nil || !strings.Contains(err.Error(), "maximum") {
		t.Fatalf("err=%v", err)
	}
}

func TestReadPasswordAdditionalLine(t *testing.T) {
	_, err := readPassword(strings.NewReader("s3cret-secure\nextra\n"), 1024)
	if err == nil {
		t.Fatal("expected reject")
	}
}

func TestReadPasswordTrailingCRPreserved(t *testing.T) {
	// Final intended character is \r (no LF): must not be stripped.
	got, err := readPassword(strings.NewReader("long-password\r"), 1024)
	if err != nil {
		t.Fatal(err)
	}

	if got != "long-password\r" {
		t.Fatalf("got %q want password ending in CR", got)
	}
}

func TestReadPasswordMinimum(t *testing.T) {
	_, err := readPassword(strings.NewReader(strings.Repeat("x", minPasswordBytes-1)), 1024)
	if err == nil || !strings.Contains(err.Error(), "at least") {
		t.Fatalf("short password err=%v", err)
	}

	_, err = readPassword(strings.NewReader(strings.Repeat("x", minPasswordBytes)), 1024)
	if err != nil {
		t.Fatalf("minimum password rejected: %v", err)
	}
}

func TestReadPasswordReadError(t *testing.T) {
	want := errors.New("boom")

	_, err := readPassword(errReader{want}, 1024)
	if !errors.Is(err, want) {
		t.Fatalf("err=%v", err)
	}
}

func TestReadPasswordNULRejected(t *testing.T) {
	_, err := readPassword(bytes.NewReader([]byte("a\x00b")), 1024)
	if err == nil {
		t.Fatal("expected NUL reject")
	}
}

func TestPasswordIntegrationOverflow(t *testing.T) {
	r, w := io.Pipe()

	go func() {
		_, _ = w.Write(bytes.Repeat([]byte("x"), 1025))
		_ = w.Close()
	}()

	_, err := readPassword(r, 1024)
	if err == nil || !strings.Contains(err.Error(), "maximum") {
		t.Fatalf("err=%v", err)
	}
}
