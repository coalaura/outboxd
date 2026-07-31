//go:build !windows

package sign

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/coalaura/outboxd/internal/config"
)

func TestLoadRejectsAccessibleAndSymlinkedKeyUnix(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Server.DataDirectory = dir
	if _, _, err := Ensure(cfg); err != nil {
		t.Fatal(err)
	}
	path, _ := cfg.ResolveGeneratedPath(cfg.DKIM.PrivateKeyFile)
	if err := os.Chmod(path, 0640); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(cfg); err == nil {
		t.Fatal("group-accessible DKIM key accepted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(dir, "real.key")
	if err := os.Rename(path, real); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, path); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(cfg); err == nil {
		t.Fatal("symlinked DKIM key accepted")
	}
}

func TestLoadRejectsSymlinkedParentUnix(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	data := filepath.Join(dir, "data")
	if err := os.MkdirAll(real, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(data, 0700); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Server.DataDirectory = real
	if _, _, err := Ensure(cfg); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(real, "dkim"), filepath.Join(data, "dkim")); err != nil {
		t.Fatal(err)
	}
	cfg.Server.DataDirectory = data
	if _, err := Load(cfg); err == nil {
		t.Fatal("Load accepted a DKIM key beneath a symlinked parent")
	}
}
