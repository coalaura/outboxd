package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/coalaura/outboxd/internal/config"
	"github.com/coalaura/outboxd/internal/disk"
)

func TestDNSDoesNotGenerateMissingDKIMKeyOrReplaceOutput(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yml")

	cfg, _, err := config.EnsurePath(configPath)
	if err != nil {
		t.Fatal(err)
	}

	dnsPath, err := cfg.ResolveGeneratedPath(cfg.DNS.OutputFile)
	if err != nil {
		t.Fatal(err)
	}

	err = disk.Write(dnsPath, []byte("published identity\n"), 0644)
	if err != nil {
		t.Fatal(err)
	}

	provisionOwnershipFiles(t, cfg)

	keyPath, err := cfg.ResolveGeneratedPath(cfg.DKIM.PrivateKeyFile)
	if err != nil {
		t.Fatal(err)
	}

	err = dns(configPath)
	if err == nil || !strings.Contains(err.Error(), "DKIM") {
		t.Fatalf("dns with missing DKIM key error=%v", err)
	}

	if _, err = os.Stat(keyPath); !os.IsNotExist(err) {
		t.Fatalf("dns generated missing DKIM key: %v", err)
	}

	body, err := os.ReadFile(dnsPath)
	if err != nil {
		t.Fatal(err)
	}

	if string(body) != "published identity\n" {
		t.Fatalf("dns replaced existing output: %q", body)
	}
}

func TestDNSMissingConfigDoesNotCreateIt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "missing.yml")

	err := dns(path)
	if err == nil {
		t.Fatal("dns with missing config succeeded")
	}

	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatalf("dns created missing config: %v", statErr)
	}

	if _, statErr := os.Stat(path + ".outboxd.lock"); !os.IsNotExist(statErr) {
		t.Fatalf("dns created ownership lock for missing config: %v", statErr)
	}
}

func TestDNSRejectsDaemonOwnedSpool(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")

	err := provision(path)
	if err != nil {
		t.Fatal(err)
	}

	err = provision(path)
	if err != nil {
		t.Fatal(err)
	}

	cfg, err := config.LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	held, err := disk.Lock(filepath.Join(cfg.ResolvePath("queue"), ".lock"))
	if err != nil {
		t.Fatal(err)
	}

	defer held.Close()

	err = dns(path)
	if !errors.Is(err, disk.ErrLocked) {
		t.Fatalf("dns while daemon owns spool error=%v, want ErrLocked", err)
	}
}

func TestDNSRejectsChangedPathsWhileStartupSnapshotOwned(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")

	cfg, _, err := config.EnsurePath(path)
	if err != nil {
		t.Fatal(err)
	}

	provisionOwnershipFiles(t, cfg)

	startup, err := disk.Lock(path + ".outboxd.lock")
	if err != nil {
		t.Fatal(err)
	}

	defer startup.Close()

	cfg.Server.DataDirectory = filepath.Join(dir, "changed-data")
	if err = cfg.Save(); err != nil {
		t.Fatal(err)
	}

	err = dns(path)
	if !errors.Is(err, disk.ErrLocked) {
		t.Fatalf("dns after configured path change error=%v, want ErrLocked", err)
	}
}
