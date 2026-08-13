package openpgp

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	pgp "github.com/ProtonMail/go-crypto/openpgp"
	"github.com/coalaura/outboxd/internal/config"
	"github.com/coalaura/outboxd/internal/disk"
	"github.com/coalaura/outboxd/internal/passwd"
)

func TestCreateGeneratesEncryptedConfiguredKey(t *testing.T) {
	cfg, path := createTestConfig(t)

	created, err := Create(path, "alice", "Alice@EXAMPLE.com")
	if err != nil {
		t.Fatal(err)
	}

	if created.Sender != "Alice@example.com" || len(created.Fingerprint) != 40 {
		t.Fatalf("unexpected created key: %+v", created)
	}

	loaded, err := config.LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	if len(loaded.OpenPGP.Identities) != 1 {
		t.Fatalf("identities=%+v", loaded.OpenPGP.Identities)
	}

	identity := loaded.OpenPGP.Identities[0]
	if identity.Sender != created.Sender || identity.Signing != "required" || identity.SigningKey != created.SigningKey || identity.PassphraseFile != created.PassphraseFile {
		t.Fatalf("configured identity=%+v created=%+v", identity, created)
	}

	_, err = Load(loaded)
	if err != nil {
		t.Fatalf("production loader rejected generated key: %v", err)
	}

	keyPath := cfg.ResolvePath(created.SigningKey)
	passPath := cfg.ResolvePath(created.PassphraseFile)

	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}

	entities, err := pgp.ReadArmoredKeyRing(bytes.NewReader(keyData))
	if err != nil || len(entities) != 1 {
		t.Fatalf("read generated key entities=%d err=%v", len(entities), err)
	}

	bits, err := entities[0].PrimaryKey.BitLength()
	if err != nil {
		t.Fatal(err)
	}

	if bits != generatedRSABits || !entities[0].PrivateKey.Encrypted {
		t.Fatalf("primary key bits=%d encrypted=%v", bits, entities[0].PrivateKey.Encrypted)
	}

	for _, subkey := range entities[0].Subkeys {
		if subkey.PrivateKey == nil || !subkey.PrivateKey.Encrypted {
			t.Fatal("generated private subkey is not encrypted")
		}
	}

	for _, privatePath := range []string{keyPath, passPath} {
		info, statErr := os.Stat(privatePath)
		if statErr != nil {
			t.Fatal(statErr)
		}

		if runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
			t.Fatalf("private file %s mode=%o", privatePath, info.Mode().Perm())
		}
	}

	before, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}

	_, err = Create(path, "alice", "Alice@example.com")
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("duplicate create error=%v", err)
	}

	after, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(before, after) {
		t.Fatal("duplicate create replaced the existing key")
	}
}

func TestCreateRequiresExactSender(t *testing.T) {
	_, path := createTestConfigWithSenders(t, []string{"*@example.com"})

	_, err := Create(path, "alice", "alice@example.com")
	if err == nil || !strings.Contains(err.Error(), "not an exact allowed sender") {
		t.Fatalf("Create error=%v", err)
	}

	loaded, loadErr := config.LoadFile(path)
	if loadErr != nil {
		t.Fatal(loadErr)
	}

	if len(loaded.OpenPGP.Identities) != 0 {
		t.Fatalf("failed create changed identities: %+v", loaded.OpenPGP.Identities)
	}
}

func TestCreateRollsBackKeyWhenPassphraseWriteFails(t *testing.T) {
	cfg, path := createTestConfig(t)

	wantErr := errors.New("injected passphrase write failure")

	disk.SetHooks(disk.Hooks{AfterSyncFile: func(path string) error {
		if strings.HasSuffix(path, ".passphrase") {
			return wantErr
		}

		return nil
	}})

	t.Cleanup(func() {
		disk.SetHooks(disk.Hooks{})
	})

	_, err := Create(path, "alice", "Alice@example.com")
	if !errors.Is(err, wantErr) {
		t.Fatalf("Create error=%v want %v", err, wantErr)
	}

	entries, readErr := os.ReadDir(filepath.Join(cfg.ResolvedDataDir(), "openpgp"))
	if readErr != nil {
		t.Fatal(readErr)
	}

	if len(entries) != 0 {
		t.Fatalf("rollback left generated files: %v", entries)
	}

	loaded, loadErr := config.LoadFile(path)
	if loadErr != nil {
		t.Fatal(loadErr)
	}

	if len(loaded.OpenPGP.Identities) != 0 {
		t.Fatalf("failed create changed config: %+v", loaded.OpenPGP.Identities)
	}
}

func TestCreateRollsBackKeyAfterDirectorySyncFailure(t *testing.T) {
	cfg, path := createTestConfig(t)

	wantErr := errors.New("injected key directory sync failure")

	var failed bool

	disk.SetHooks(disk.Hooks{BeforeSyncDir: func(path string) error {
		if !failed && filepath.Base(path) == "openpgp" {
			failed = true

			return wantErr
		}

		return nil
	}})

	t.Cleanup(func() {
		disk.SetHooks(disk.Hooks{})
	})

	_, err := Create(path, "alice", "Alice@example.com")
	if !errors.Is(err, wantErr) {
		t.Fatalf("Create error=%v want %v", err, wantErr)
	}

	entries, readErr := os.ReadDir(filepath.Join(cfg.ResolvedDataDir(), "openpgp"))
	if readErr != nil {
		t.Fatal(readErr)
	}

	if len(entries) != 0 {
		t.Fatalf("rollback left generated files: %v", entries)
	}
}

func TestCreateConfigCommitFailureBeforeRenameRollsBackFiles(t *testing.T) {
	cfg, path := createTestConfig(t)

	wantErr := errors.New("injected config rename failure")

	disk.SetHooks(disk.Hooks{BeforeRename: func(_, newPath string) error {
		if newPath == path {
			return wantErr
		}

		return nil
	}})

	t.Cleanup(func() {
		disk.SetHooks(disk.Hooks{})
	})

	_, err := Create(path, "alice", "Alice@example.com")
	if !errors.Is(err, wantErr) {
		t.Fatalf("Create error=%v want %v", err, wantErr)
	}

	assertNoGeneratedFiles(t, cfg)

	loaded, loadErr := config.LoadFile(path)
	if loadErr != nil {
		t.Fatal(loadErr)
	}

	if len(loaded.OpenPGP.Identities) != 0 {
		t.Fatalf("pre-rename failure changed config: %+v", loaded.OpenPGP.Identities)
	}
}

func TestCreateConfigCommitFailureAfterRenamePreservesFiles(t *testing.T) {
	cfg, path := createTestConfig(t)

	wantErr := errors.New("injected config post-rename failure")

	disk.SetHooks(disk.Hooks{AfterRename: func(_, newPath string) error {
		if newPath == path {
			return wantErr
		}

		return nil
	}})

	t.Cleanup(func() {
		disk.SetHooks(disk.Hooks{})
	})

	_, err := Create(path, "alice", "Alice@example.com")
	if !errors.Is(err, wantErr) || !strings.Contains(err.Error(), "config was replaced") {
		t.Fatalf("Create error=%v", err)
	}

	loaded, loadErr := config.LoadFile(path)
	if loadErr != nil {
		t.Fatal(loadErr)
	}

	if len(loaded.OpenPGP.Identities) != 1 {
		t.Fatalf("post-rename config identities=%+v", loaded.OpenPGP.Identities)
	}

	identity := loaded.OpenPGP.Identities[0]

	for _, relative := range []string{identity.SigningKey, identity.PassphraseFile} {
		if _, statErr := os.Stat(cfg.ResolvePath(relative)); statErr != nil {
			t.Fatalf("committed identity file %s was not preserved: %v", relative, statErr)
		}
	}
}

func createTestConfig(t *testing.T) (*config.Config, string) {
	t.Helper()

	return createTestConfigWithSenders(t, []string{"Alice@example.com"})
}

func createTestConfigWithSenders(t *testing.T, senders []string) (*config.Config, string) {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")

	cfg, created, err := config.EnsurePath(path)
	if err != nil || !created {
		t.Fatalf("EnsurePath created=%v err=%v", created, err)
	}

	cfg.Server.Hostname = "mail.example.com"
	cfg.Server.Domain = "example.com"

	err = cfg.Init()
	if err != nil {
		t.Fatal(err)
	}

	err = cfg.Save()
	if err != nil {
		t.Fatal(err)
	}

	hash, err := passwd.Hash("test-password-123")
	if err != nil {
		t.Fatal(err)
	}

	err = cfg.AddUser(config.User{Username: "alice", PasswordHash: hash, AllowedSenders: senders, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}

	return cfg, path
}

func assertNoGeneratedFiles(t *testing.T, cfg *config.Config) {
	t.Helper()

	entries, err := os.ReadDir(filepath.Join(cfg.ResolvedDataDir(), "openpgp"))
	if err != nil {
		t.Fatal(err)
	}

	if len(entries) != 0 {
		t.Fatalf("rollback left generated files: %v", entries)
	}
}
