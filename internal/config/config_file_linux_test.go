//go:build linux

package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateConfigPermissionsAllowsRootProcess(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}

	path := filepath.Join(t.TempDir(), "config.yml")

	err := os.WriteFile(path, []byte("test"), 0600)
	if err != nil {
		t.Fatal(err)
	}

	gid := 65534

	for processHasGroup(gid) {
		gid++
	}

	err = os.Chown(path, 0, gid)
	if err != nil {
		t.Fatal(err)
	}

	err = os.Chmod(path, 0440)
	if err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	err = validateConfigPermissions(info)
	if err != nil {
		t.Fatalf("root process rejected root-owned 0440 config: %v", err)
	}
}
