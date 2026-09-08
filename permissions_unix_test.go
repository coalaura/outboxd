//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/coalaura/outboxd/internal/config"
	"github.com/coalaura/outboxd/internal/disk"
	"github.com/coalaura/outboxd/internal/sign"
)

func TestRepairPermissionsRepairsManagedTree(t *testing.T) {
	directory := t.TempDir()
	configPath := filepath.Join(directory, "config.yml")

	err := provision(configPath)
	if err != nil {
		t.Fatal(err)
	}

	err = provision(configPath)
	if err != nil {
		t.Fatal(err)
	}

	cfg, err := config.LoadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}

	openPGPDirectory := cfg.ResolvePath(filepath.Join("openpgp", "senders"))

	err = os.MkdirAll(openPGPDirectory, 0755)
	if err != nil {
		t.Fatal(err)
	}

	openPGPKey := filepath.Join(openPGPDirectory, "sender.private.asc")

	err = os.WriteFile(openPGPKey, []byte("private"), 0644)
	if err != nil {
		t.Fatal(err)
	}

	dkimKey, err := cfg.ResolveGeneratedPath(cfg.DKIM.PrivateKeyFile)
	if err != nil {
		t.Fatal(err)
	}

	damagedModes := map[string]os.FileMode{
		configPath:                                       0666,
		configPath + ".outboxd.lock":                     0644,
		cfg.ResolvedDataDir():                            0755,
		cfg.ResolvePath("queue"):                         0755,
		cfg.ResolvePath(filepath.Join("queue", ".lock")): 0644,
		dkimKey:          0644,
		openPGPDirectory: 0755,
		openPGPKey:       0644,
	}

	for path, mode := range damagedModes {
		err = os.Chmod(path, mode)
		if err != nil {
			t.Fatal(err)
		}
	}

	err = repairPermissions(configPath)
	if err != nil {
		t.Fatal(err)
	}

	dataInfo, err := os.Stat(cfg.ResolvedDataDir())
	if err != nil {
		t.Fatal(err)
	}

	dataOwner := dataInfo.Sys().(*syscall.Stat_t)

	err = filepath.Walk(cfg.ResolvedDataDir(), func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		wantMode := os.FileMode(0600)

		if info.IsDir() {
			wantMode = 0700
		}

		if info.Mode().Perm() != wantMode {
			t.Errorf("%s mode=%04o, want %04o", path, info.Mode().Perm(), wantMode)
		}

		owner := info.Sys().(*syscall.Stat_t)
		if owner.Uid != dataOwner.Uid || owner.Gid != dataOwner.Gid {
			t.Errorf("%s owner=%d:%d, want %d:%d", path, owner.Uid, owner.Gid, dataOwner.Uid, dataOwner.Gid)
		}

		return nil
	})

	if err != nil {
		t.Fatal(err)
	}

	configInfo, err := os.Stat(configPath)
	if err != nil {
		t.Fatal(err)
	}

	wantConfigMode := os.FileMode(0600)

	if os.Geteuid() == 0 {
		wantConfigMode = 0440
	}

	if configInfo.Mode().Perm() != wantConfigMode {
		t.Fatalf("config mode=%04o, want %04o", configInfo.Mode().Perm(), wantConfigMode)
	}

	_, err = sign.Load(cfg)
	if err != nil {
		t.Fatalf("repaired DKIM key cannot be loaded: %v", err)
	}

	err = disk.ValidatePrivateTree(cfg.ResolvedDataDir())
	if err != nil {
		t.Fatalf("repaired data tree is invalid: %v", err)
	}
}

func TestRepairPrivateTreeRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(t.TempDir(), "target")

	err := os.WriteFile(target, []byte("external"), 0600)
	if err != nil {
		t.Fatal(err)
	}

	err = os.Symlink(target, filepath.Join(root, "linked"))
	if err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	err = disk.RepairPrivateTree(root)
	if err == nil {
		t.Fatal("repair accepted symlink")
	}
}
