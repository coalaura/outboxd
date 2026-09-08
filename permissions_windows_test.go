//go:build windows

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/coalaura/outboxd/internal/config"
	"github.com/coalaura/outboxd/internal/disk"
	"golang.org/x/sys/windows"
)

func TestRepairPermissionsRepairsManagedDACLs(t *testing.T) {
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

	dkimKey, err := cfg.ResolveGeneratedPath(cfg.DKIM.PrivateKeyFile)
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile(configPath+".lock", nil, 0600)
	if err != nil {
		t.Fatal(err)
	}

	damagedPaths := []string{
		configPath,
		configPath + ".lock",
		configPath + ".outboxd.lock",
		cfg.ResolvedDataDir(),
		cfg.ResolvePath("queue"),
		cfg.ResolvePath(filepath.Join("queue", ".lock")),
		dkimKey,
	}

	for _, path := range damagedPaths {
		setBroadTestDACL(t, path)
	}

	err = repairPermissions(configPath)
	if err != nil {
		t.Fatal(err)
	}

	_, err = config.LoadFile(configPath)
	if err != nil {
		t.Fatalf("repaired config cannot be loaded: %v", err)
	}

	lockPaths := []string{configPath + ".lock", configPath + ".outboxd.lock"}

	for _, lockPath := range lockPaths {
		err = config.CheckFile(lockPath, true)
		if err != nil {
			t.Errorf("repaired config lock %s is invalid: %v", lockPath, err)
		}
	}

	err = disk.ValidatePrivateTree(cfg.ResolvedDataDir())
	if err != nil {
		t.Fatalf("repaired data tree is invalid: %v", err)
	}
}

func setBroadTestDACL(t *testing.T, path string) {
	t.Helper()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	flags := ""

	if info.IsDir() {
		flags = "OICI"
	}

	sd, err := windows.SecurityDescriptorFromString("D:P(A;" + flags + ";FA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}

	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}

	err = windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		dacl,
		nil,
	)

	if err != nil {
		t.Fatal(err)
	}
}
