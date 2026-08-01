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
	_, _, err := Ensure(cfg)
	if err != nil {
		t.Fatal(err)
	}

	path, _ := cfg.ResolveGeneratedPath(cfg.DKIM.PrivateKeyFile)
	err := os.Chmod(path, 0640)
	if err != nil {
		t.Fatal(err)
	}

	_, err := Load(cfg)
	if err == nil {
		t.Fatal("group-accessible DKIM key accepted")
	}

	err := os.Chmod(path, 0600)
	if err != nil {
		t.Fatal(err)
	}

	real := filepath.Join(dir, "real.key")
	err := os.Rename(path, real)
	if err != nil {
		t.Fatal(err)
	}

	err := os.Symlink(real, path)
	if err != nil {
		t.Fatal(err)
	}

	_, err := Load(cfg)
	if err == nil {
		t.Fatal("symlinked DKIM key accepted")
	}
}

func TestLoadRejectsSymlinkedParentUnix(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	data := filepath.Join(dir, "data")
	err := os.MkdirAll(real, 0700)
	if err != nil {
		t.Fatal(err)
	}

	err := os.MkdirAll(data, 0700)
	if err != nil {
		t.Fatal(err)
	}

	cfg := config.Default()
	cfg.Server.DataDirectory = real
	_, _, err := Ensure(cfg)
	if err != nil {
		t.Fatal(err)
	}

	err := os.Symlink(filepath.Join(real, "dkim"), filepath.Join(data, "dkim"))
	if err != nil {
		t.Fatal(err)
	}

	cfg.Server.DataDirectory = data
	_, err := Load(cfg)
	if err == nil {
		t.Fatal("Load accepted a DKIM key beneath a symlinked parent")
	}
}
