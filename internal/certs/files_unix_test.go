//go:build !windows

package certs

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEnsureRejectsAccessibleAndAllowsOperatorSymlinkUnix(t *testing.T) {
	dir := t.TempDir()
	if err := writeSelfSigned(dir, "mail.test.example"); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(dir, "server.key")
	if err := os.Chmod(key, 0640); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ensureWithDir(t, dir, "files"); err == nil {
		t.Fatal("group-accessible TLS key accepted")
	}
	if err := os.Chmod(key, 0600); err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(dir, "real.key")
	if err := os.Rename(key, real); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, key); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ensureWithDir(t, dir, "files"); err != nil {
		t.Fatalf("operator-managed symlink to secure regular key rejected: %v", err)
	}
}
