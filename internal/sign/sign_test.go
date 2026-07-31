package sign

import (
	"os"
	"path/filepath"
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
