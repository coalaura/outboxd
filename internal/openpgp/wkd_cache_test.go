package openpgp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/coalaura/outboxd/internal/config"
	"github.com/coalaura/outboxd/internal/disk"
)

func TestWKDRecipientsCacheAndScope(t *testing.T) {
	entity, _ := newWKDTestKey(t, "bob@example.com", nil)

	err := entity.AddUserId("Alias", "", "alias@example.com", nil)
	if err != nil {
		t.Fatal(err)
	}

	var public bytes.Buffer

	err = entity.Serialize(&public)
	if err != nil {
		t.Fatal(err)
	}

	cfg := newWKDTestConfig(t)
	lookups := 0

	lookup := func(ctx context.Context, recipient string) ([]byte, error) {
		lookups++

		if recipient != "bob@example.com" {
			t.Fatalf("unexpected lookup for %q", recipient)
		}

		return bytes.Clone(public.Bytes()), nil
	}

	first, err := loadRecipients(cfg, lookup)
	if err != nil {
		t.Fatal(err)
	}

	keyID, found, err := first.KeyID("bob@example.com")
	if err != nil || !found || keyID == "" {
		t.Fatalf("KeyID() = %q, %v, %v", keyID, found, err)
	}

	_, found, err = first.KeyID("alias@example.com")
	if err != nil || found {
		t.Fatalf("unrequested alias KeyID() = %v, %v", found, err)
	}

	second, err := loadRecipients(cfg, lookup)
	if err != nil || lookups != 1 {
		t.Fatalf("cached loadRecipients() = %v, lookups = %d", err, lookups)
	}

	cachedID, found, err := second.KeyID("bob@example.com")
	if err != nil || !found || cachedID != keyID {
		t.Fatalf("cached KeyID() = %q, %v, %v", cachedID, found, err)
	}

	path, err := wkdCachePath(cfg, "bob@example.com")
	if err != nil {
		t.Fatal(err)
	}

	err = config.CheckFile(path, true)
	if err != nil {
		t.Fatalf("cache is not private: %v", err)
	}

	otherPath, err := wkdCachePath(cfg, "Bob@example.com")
	if err != nil || otherPath == path {
		t.Fatalf("case-distinct cache path = %q, %v", otherPath, err)
	}
}

func TestWKDRecipientsLocalPrecedenceAndOptIn(t *testing.T) {
	_, public := newWKDTestKey(t, "bob@example.com", nil)

	cfg := newWKDTestConfig(t)
	cfg.OpenPGP.RecipientKeysDirectory = "recipients"

	directory := cfg.ResolvePath("recipients")

	err := disk.MkdirDurable(directory)
	if err != nil {
		t.Fatal(err)
	}

	err = disk.Write(filepath.Join(directory, "bob.pgp"), public, 0600)
	if err != nil {
		t.Fatal(err)
	}

	lookup := func(context.Context, string) ([]byte, error) {
		t.Fatal("unexpected WKD lookup")

		return nil, nil
	}

	_, err = loadRecipients(cfg, lookup)
	if err != nil {
		t.Fatal(err)
	}

	cfg.OpenPGP.RecipientKeysDirectory = ""
	cfg.OpenPGP.UseWKD = false

	_, err = loadRecipients(cfg, lookup)
	if err == nil {
		t.Fatal("missing required key accepted with WKD disabled")
	}

	cfg.OpenPGP.UseWKD = true
	cfg.OpenPGP.RequireEncryptionFor = nil

	_, err = loadRecipients(cfg, lookup)
	if err != nil {
		t.Fatal(err)
	}

	_, err = os.Stat(cfg.ResolvePath("openpgp/cache"))
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unused cache directory was created: %v", err)
	}
}

func TestWKDCacheRefreshAndFailure(t *testing.T) {
	_, public := newWKDTestKey(t, "bob@example.com", nil)
	_, wrong := newWKDTestKey(t, "other@example.com", nil)

	tests := []string{"stale", "future", "invalid key", "lookup failure", "invalid lookup"}

	for _, name := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := newWKDTestConfig(t)
			entry := wkdCacheEntry{Recipient: "bob@example.com", FetchedAt: time.Now().Add(-25 * time.Hour), Key: public}

			switch name {
			case "future":
				entry.FetchedAt = time.Now().Add(time.Hour)
			case "invalid key":
				entry.FetchedAt = time.Now()
				entry.Key = wrong
			}

			path := writeWKDTestCache(t, cfg, entry)
			lookups := 0

			lookup := func(context.Context, string) ([]byte, error) {
				lookups++

				if name == "lookup failure" {
					return nil, errors.New("offline")
				}

				if name == "invalid lookup" {
					return bytes.Clone(wrong), nil
				}

				return bytes.Clone(public), nil
			}

			recipients, err := loadRecipients(cfg, lookup)

			if lookups != 1 {
				t.Fatalf("lookup count = %d", lookups)
			}

			if name == "lookup failure" || name == "invalid lookup" {
				if err == nil || recipients != nil {
					t.Fatalf("stale key rescued failed lookup: %v", err)
				}

				return
			}

			if err != nil {
				t.Fatal(err)
			}

			cached, err := readWKDCache(path, "bob@example.com")
			if err != nil || cached == nil {
				t.Fatalf("refreshed cache = %v, %v", cached, err)
			}
		})
	}
}

func TestWKDCacheRejectsUnsafeState(t *testing.T) {
	_, public := newWKDTestKey(t, "bob@example.com", nil)

	tests := []string{"mismatched recipient", "malformed", "directory entry", "symlink", "public file", "public directory"}

	for _, name := range tests {
		t.Run(name, func(t *testing.T) {
			if runtime.GOOS == "windows" && (name == "symlink" || strings.HasPrefix(name, "public ")) {
				t.Skip("Unix mode and unprivileged symlink checks")
			}

			cfg := newWKDTestConfig(t)

			entry := wkdCacheEntry{Recipient: "bob@example.com", FetchedAt: time.Now(), Key: public}

			path := writeWKDTestCache(t, cfg, entry)

			var err error

			switch name {
			case "mismatched recipient":
				entry.Recipient = "other@example.com"
				writeWKDTestCache(t, cfg, entry)
			case "malformed":
				err = disk.Write(path, []byte("{"), 0600)
			case "directory entry", "symlink":
				err = os.Remove(path)
				if err != nil {
					t.Fatal(err)
				}

				if name == "directory entry" {
					err = os.Mkdir(path, 0700)
				} else {
					err = os.Symlink(cfg.ResolvedDataDir(), path)
				}
			case "public file":
				err = os.Chmod(path, 0644)
			case "public directory":
				err = os.Chmod(filepath.Dir(path), 0755)
			}

			if err != nil {
				t.Fatal(err)
			}

			lookup := func(context.Context, string) ([]byte, error) {
				t.Fatal("unsafe cache permitted network discovery")

				return nil, nil
			}

			_, err = loadRecipients(cfg, lookup)
			if err == nil {
				t.Fatal("unsafe cache accepted")
			}
		})
	}
}

func TestWKDCacheWriteFailureRejectsKey(t *testing.T) {
	_, public := newWKDTestKey(t, "bob@example.com", nil)

	cfg := newWKDTestConfig(t)

	lookup := func(context.Context, string) ([]byte, error) {
		// A namespace change between discovery and persistence must fail closed.
		err := disk.Write(cfg.ResolvePath("openpgp"), []byte("not a directory"), 0600)
		if err != nil {
			t.Fatal(err)
		}

		return bytes.Clone(public), nil
	}

	recipients, err := loadRecipients(cfg, lookup)
	if err == nil || recipients != nil {
		t.Fatalf("key selected after cache write failure: %v", err)
	}
}

func TestWKDCacheWindowsPathCase(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows path case equivalence")
	}

	cfg := newWKDTestConfig(t)
	cfg.OpenPGP.WKDCacheDirectory = filepath.Join(strings.ToUpper(cfg.ResolvedDataDir()), "cache")

	_, err := wkdCachePath(cfg, "bob@example.com")
	if err != nil {
		t.Fatalf("case-equivalent cache path: %v", err)
	}
}

func newWKDTestConfig(t *testing.T) *config.Config {
	t.Helper()

	directory := filepath.Join(t.TempDir(), "data")

	err := disk.EnsurePrivateRoot(directory)
	if err != nil {
		t.Fatal(err)
	}

	return &config.Config{
		Server: config.Server{DataDirectory: directory, MaxMessageBytes: 1 << 20},
		OpenPGP: config.OpenPGP{
			UseWKD:               true,
			RequireEncryptionFor: []string{"bob@example.com"},
		},
	}
}

func writeWKDTestCache(t *testing.T, cfg *config.Config, entry wkdCacheEntry) string {
	t.Helper()

	path, err := wkdCachePath(cfg, "bob@example.com")
	if err != nil {
		t.Fatal(err)
	}

	err = disk.MkdirDurable(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}

	body, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}

	err = disk.Write(path, body, 0600)
	if err != nil {
		t.Fatal(err)
	}

	return path
}
