//go:build !windows

package openpgp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCreateRejectsPermissiveOpenPGPDirectory(t *testing.T) {
	cfg, path := createTestConfig(t)

	directory := filepath.Join(cfg.ResolvedDataDir(), "openpgp")

	err := os.MkdirAll(directory, 0770)
	if err != nil {
		t.Fatal(err)
	}

	err = os.Chmod(directory, 0770)
	if err != nil {
		t.Fatal(err)
	}

	_, err = Create(path, "alice", "Alice@example.com")
	if err == nil || !strings.Contains(err.Error(), "allow group or other access") {
		t.Fatalf("Create error=%v", err)
	}

	entries, readErr := os.ReadDir(directory)
	if readErr != nil {
		t.Fatal(readErr)
	}

	if len(entries) != 0 {
		t.Fatalf("rejected directory contains generated files: %v", entries)
	}
}

func TestCreateRejectsLinkedOpenPGPDirectory(t *testing.T) {
	cfg, path := createTestConfig(t)

	external := t.TempDir()

	err := os.MkdirAll(cfg.ResolvedDataDir(), 0700)
	if err != nil {
		t.Fatal(err)
	}

	err = os.Symlink(external, filepath.Join(cfg.ResolvedDataDir(), "openpgp"))
	if err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	_, err = Create(path, "alice", "Alice@example.com")
	if err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("Create error=%v", err)
	}

	entries, readErr := os.ReadDir(external)
	if readErr != nil {
		t.Fatal(readErr)
	}

	if len(entries) != 0 {
		t.Fatalf("linked directory received generated files: %v", entries)
	}
}
