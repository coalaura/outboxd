//go:build linux

package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfigFileOwnerFromFileInfo(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yml")

	err := os.WriteFile(path, []byte("server: {}\n"), 0600)
	if err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	uid, gid, ok := configFileOwner(info)
	if !ok {
		t.Fatal("could not read Linux ownership from os.FileInfo")
	}

	if uid != uint32(os.Getuid()) || gid != os.Getgid() {
		t.Fatalf("owner = %d:%d, want %d:%d", uid, gid, os.Getuid(), os.Getgid())
	}
}
