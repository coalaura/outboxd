//go:build !windows

package certs

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEnsureRejectsAccessibleAndAllowsOperatorSymlinkUnix(t *testing.T) {
	dir := t.TempDir()

	err := writeSelfSigned(dir, "mail.test.example")
	if err != nil {
		t.Fatal(err)
	}

	key := filepath.Join(dir, "server.key")

	err = os.Chmod(key, 0640)
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = ensureWithDir(t, dir, "files")
	if err == nil {
		t.Fatal("group-accessible TLS key accepted")
	}

	err = os.Chmod(key, 0600)
	if err != nil {
		t.Fatal(err)
	}

	real := filepath.Join(dir, "real.key")

	err = os.Rename(key, real)
	if err != nil {
		t.Fatal(err)
	}

	err = os.Symlink(real, key)
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = ensureWithDir(t, dir, "files")
	if err != nil {
		t.Fatalf("operator-managed symlink to secure regular key rejected: %v", err)
	}
}
