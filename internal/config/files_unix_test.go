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

	err := os.WriteFile(path, []byte("secret"), 0644)
	if err != nil {
		t.Fatal(err)
	}

	err = CheckFile(path, true)
	if err == nil {
		t.Fatal("group/other-accessible private file accepted")
	}

	err = os.Chmod(path, 0600)
	if err != nil {
		t.Fatal(err)
	}

	err = CheckFile(path, true)
	if err != nil {
		t.Fatal(err)
	}

	link := filepath.Join(dir, "link")

	err = os.Symlink(path, link)
	if err != nil {
		t.Fatal(err)
	}

	err = CheckFile(link, true)
	if err == nil {
		t.Fatal("symlinked private file accepted")
	}
}

func TestGeneratedSymlinkParentRejectedUnix(t *testing.T) {
	dir := t.TempDir()
	realDir := filepath.Join(dir, "real")

	err := os.Mkdir(realDir, 0700)
	if err != nil {
		t.Fatal(err)
	}

	data := filepath.Join(dir, "data")

	err = os.Mkdir(data, 0700)
	if err != nil {
		t.Fatal(err)
	}

	err = os.Symlink(realDir, filepath.Join(data, "keys"))
	if err != nil {
		t.Fatal(err)
	}

	cfg := Default()

	cfg.Server.DataDirectory = data

	path, err := cfg.ResolveGeneratedPath("keys/mail.key")
	if err != nil {
		t.Fatal(err)
	}

	err = cfg.CheckGeneratedParents(path)
	if err == nil {
		t.Fatal("symlinked generated parent accepted")
	}
}

func TestReadCheckedFileLimitUnix(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bounded")

	err := os.WriteFile(path, []byte("12345"), 0600)
	if err != nil {
		t.Fatal(err)
	}

	_, err = ReadCheckedFile(path, true, false, 4)
	if err == nil {
		t.Fatal("oversized checked file accepted")
	}

	body, err := ReadCheckedFile(path, true, false, 5)
	if err != nil || string(body) != "12345" {
		t.Fatalf("exact-limit read body=%q err=%v", body, err)
	}
}
