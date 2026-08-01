package sign

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/coalaura/outboxd/internal/config"
)

func TestLoadIsReadOnly(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Server.DataDirectory = dir
	path := filepath.Join(dir, cfg.DKIM.PrivateKeyFile)
	_, err := Load(cfg)
	if err == nil {
		t.Fatal("missing key must fail")
	}

	_, err = os.Stat(path)
	if !os.IsNotExist(err) {
		t.Fatalf("Load created missing key: %v", err)
	}

	err = os.MkdirAll(filepath.Dir(path), 0700)
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile(path, []byte("malformed"), 0600)
	if err != nil {
		t.Fatal(err)
	}

	before, _ := os.ReadFile(path)
	_, err = Load(cfg)
	if err == nil {
		t.Fatal("malformed key must fail")
	}

	after, _ := os.ReadFile(path)
	if string(after) != string(before) {
		t.Fatal("Load mutated malformed key")
	}
}

func TestEnsureCreatesKeyOnce(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Server.DataDirectory = dir

	first, created, err := Ensure(cfg)
	if err != nil {
		t.Fatal(err)
	}

	if !created {
		t.Fatal("first provision did not create key")
	}

	path := filepath.Join(dir, cfg.DKIM.PrivateKeyFile)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	second, created, err := Ensure(cfg)
	if err != nil {
		t.Fatal(err)
	}

	if created {
		t.Fatal("second provision replaced key")
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	if string(after) != string(before) || second.PublicKey != first.PublicKey {
		t.Fatal("second provision changed key identity")
	}
}

func TestEnsureDoesNotReplaceMalformedExistingKey(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Server.DataDirectory = dir
	path := filepath.Join(dir, cfg.DKIM.PrivateKeyFile)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}

	before := []byte("not a private key\n")
	if err := os.WriteFile(path, before, 0600); err != nil {
		t.Fatal(err)
	}

	if _, _, err := Ensure(cfg); err == nil {
		t.Fatal("provision accepted malformed existing key")
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	if string(after) != string(before) {
		t.Fatal("provision replaced malformed existing key")
	}
}

func TestParseKeyRejectsWeakAndInvalidRSA(t *testing.T) {
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}

	body := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(weak)})
	_, err = parseKey(body)
	if err == nil || !strings.Contains(err.Error(), "at least 2048 bits") {
		t.Fatalf("weak RSA key error=%v", err)
	}

	invalid := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), 2047), E: 65537},
		D:         big.NewInt(1),
		Primes:    []*big.Int{big.NewInt(3), big.NewInt(5)},
	}
	_, err = validateKey(invalid)
	if err == nil || !strings.Contains(err.Error(), "invalid dkim RSA") {
		t.Fatalf("mathematically invalid RSA key error=%v", err)
	}
}

func TestDKIMKeyReadLimit(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Server.DataDirectory = dir
	path := filepath.Join(dir, cfg.DKIM.PrivateKeyFile)
	err := os.MkdirAll(filepath.Dir(path), 0700)
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile(path, make([]byte, maxPrivateKeyBytes+1), 0600)
	if err != nil {
		t.Fatal(err)
	}

	_, err = Load(cfg)
	if err == nil || !strings.Contains(err.Error(), "read limit") {
		t.Fatalf("oversized DKIM key error=%v", err)
	}
}
