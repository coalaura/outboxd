//go:build !windows

package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPrivateFileSecurityUnix(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "private")
	if err := os.WriteFile(path, []byte("secret"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := CheckFile(path, true); err == nil {
		t.Fatal("group/other-accessible private file accepted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := CheckFile(path, true); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if err := CheckFile(link, true); err == nil {
		t.Fatal("symlinked private file accepted")
	}
}

func TestGeneratedSymlinkParentRejectedUnix(t *testing.T) {
	dir := t.TempDir()
	realDir := filepath.Join(dir, "real")
	if err := os.Mkdir(realDir, 0700); err != nil {
		t.Fatal(err)
	}
	data := filepath.Join(dir, "data")
	if err := os.Mkdir(data, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realDir, filepath.Join(data, "keys")); err != nil {
		t.Fatal(err)
	}
	cfg := Default()
	cfg.Server.DataDirectory = data
	path, err := cfg.ResolveGeneratedPath("keys/mail.key")
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.CheckGeneratedParents(path); err == nil {
		t.Fatal("symlinked generated parent accepted")
	}
}

func TestReadCheckedFileLimitUnix(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bounded")
	if err := os.WriteFile(path, []byte("12345"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadCheckedFile(path, true, false, 4); err == nil {
		t.Fatal("oversized checked file accepted")
	}
	body, err := ReadCheckedFile(path, true, false, 5)
	if err != nil || string(body) != "12345" {
		t.Fatalf("exact-limit read body=%q err=%v", body, err)
	}
}
