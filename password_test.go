package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
)

// readPasswordFrom is the testable core of password stdin handling.
func readPasswordFrom(r io.Reader, maxBytes int) (string, error) {
	body, err := io.ReadAll(io.LimitReader(r, int64(maxBytes)+1))
	if err != nil {
		return "", err
	}
	if len(body) > maxBytes {
		return "", errors.New("password exceeds maximum length")
	}
	supplied := strings.TrimRight(string(body), "\r\n")
	if supplied == "" {
		return "", errors.New("empty password on stdin")
	}
	return supplied, nil
}

func TestReadPasswordEmpty(t *testing.T) {
	_, err := readPasswordFrom(strings.NewReader(""), 1024)
	if err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("err=%v", err)
	}
}

func TestReadPasswordNormal(t *testing.T) {
	got, err := readPasswordFrom(strings.NewReader("s3cret\n"), 1024)
	if err != nil {
		t.Fatal(err)
	}
	if got != "s3cret" {
		t.Fatalf("got %q", got)
	}
}

func TestReadPasswordCRLF(t *testing.T) {
	got, err := readPasswordFrom(strings.NewReader("s3cret\r\n"), 1024)
	if err != nil {
		t.Fatal(err)
	}
	if got != "s3cret" {
		t.Fatalf("got %q", got)
	}
}

func TestReadPasswordMaxLength(t *testing.T) {
	const max = 16
	pw := strings.Repeat("a", max)
	got, err := readPasswordFrom(strings.NewReader(pw), max)
	if err != nil {
		t.Fatal(err)
	}
	if got != pw {
		t.Fatal("max length not accepted")
	}
}

func TestReadPasswordMaxPlusOne(t *testing.T) {
	const max = 16
	pw := strings.Repeat("a", max+1)
	_, err := readPasswordFrom(strings.NewReader(pw), max)
	if err == nil || !strings.Contains(err.Error(), "maximum") {
		t.Fatalf("err=%v", err)
	}
}

func TestPasswordFunctionMatchesLimits(t *testing.T) {
	// Ensure production password() path rejects overflow (integration-ish via pipe).
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = old; _ = r.Close() })

	// Write max+1 bytes without waiting (pipe buffer is larger).
	go func() {
		_, _ = w.Write(bytes.Repeat([]byte("x"), 1025))
		_ = w.Close()
	}()
	_, _, err = password()
	if err == nil || !strings.Contains(err.Error(), "maximum") {
		t.Fatalf("password() err=%v", err)
	}
}
