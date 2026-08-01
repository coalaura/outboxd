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
	if _, err := Load(cfg); err == nil {
		t.Fatal("missing key must fail")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("Load created missing key: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("malformed"), 0600); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	if _, err := Load(cfg); err == nil {
		t.Fatal("malformed key must fail")
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(before) {
		t.Fatal("Load mutated malformed key")
	}
}

func TestParseKeyRejectsWeakAndInvalidRSA(t *testing.T) {
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	body := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(weak)})
	if _, err := parseKey(body); err == nil || !strings.Contains(err.Error(), "at least 2048 bits") {
		t.Fatalf("weak RSA key error=%v", err)
	}
	invalid := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), 2047), E: 65537},
		D:         big.NewInt(1),
		Primes:    []*big.Int{big.NewInt(3), big.NewInt(5)},
	}
	if _, err := validateKey(invalid); err == nil || !strings.Contains(err.Error(), "invalid dkim RSA") {
		t.Fatalf("mathematically invalid RSA key error=%v", err)
	}
}

func TestDKIMKeyReadLimit(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Server.DataDirectory = dir
	path := filepath.Join(dir, cfg.DKIM.PrivateKeyFile)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, make([]byte, maxPrivateKeyBytes+1), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(cfg); err == nil || !strings.Contains(err.Error(), "read limit") {
		t.Fatalf("oversized DKIM key error=%v", err)
	}
}
