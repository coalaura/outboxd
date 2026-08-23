package openpgp

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pgp "github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/coalaura/outboxd/internal/config"
	"github.com/coalaura/outboxd/internal/disk"
)

func TestPublishCreatesPublicKeysAndBothWKDLayouts(t *testing.T) {
	directory := t.TempDir()
	configPath := filepath.Join(directory, "outboxd.yml")

	cfg, _, err := config.EnsurePath(configPath)
	if err != nil {
		t.Fatal(err)
	}

	entity, err := pgp.NewEntity("Alice", "", "alice@example.com", &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA})
	if err != nil {
		t.Fatal(err)
	}

	var private bytes.Buffer

	armored, err := armor.Encode(&private, pgp.PrivateKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}

	err = entity.SerializePrivate(armored, nil)
	if err == nil {
		err = armored.Close()
	} else {
		_ = armored.Close()
	}

	if err != nil {
		t.Fatal(err)
	}

	keyPath := cfg.ResolvePath("openpgp/alice.asc")

	err = disk.WriteExclusive(keyPath, private.Bytes(), 0600)
	if err != nil {
		t.Fatal(err)
	}

	cfg.OpenPGP.Identities = []config.OpenPGPIdentity{{Sender: "alice@example.com", SigningKey: "openpgp/alice.asc", Signing: "required"}}

	err = cfg.Save()
	if err != nil {
		t.Fatal(err)
	}

	output := filepath.Join(directory, "publication")

	results, err := Publish(configPath, output)
	if err != nil {
		t.Fatal(err)
	}

	if len(results) != 1 || results[0].Sender != "alice@example.com" {
		t.Fatalf("Publish() results = %+v", results)
	}

	for _, path := range []string{results[0].PublicKey, results[0].AdvancedWKD, results[0].DirectWKD} {
		body, err := os.ReadFile(path)
		if err != nil || len(body) == 0 {
			t.Fatalf("read artifact %s: bytes=%d err=%v", path, len(body), err)
		}
	}

	advancedPolicy := filepath.Join(output, "wkd", "advanced", "openpgpkey.example.com", ".well-known", "openpgpkey", "example.com", "policy")
	directPolicy := filepath.Join(output, "wkd", "direct", "example.com", ".well-known", "openpgpkey", "policy")

	for _, path := range []string{advancedPolicy, directPolicy} {
		body, err := os.ReadFile(path)
		if err != nil || len(body) != 0 {
			t.Fatalf("WKD policy %s: bytes=%d err=%v", path, len(body), err)
		}
	}

	manifest, err := os.ReadFile(filepath.Join(output, "MANIFEST.txt"))
	if err != nil || !strings.Contains(string(manifest), "https://openpgpkey.example.com/") {
		t.Fatalf("manifest error=%v body=%s", err, manifest)
	}

	_, err = Publish(configPath, output)
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("second Publish() error = %v", err)
	}
}

func TestPublishFailureDoesNotLeaveTarget(t *testing.T) {
	directory := t.TempDir()
	configPath := filepath.Join(directory, "outboxd.yml")

	cfg, _, err := config.EnsurePath(configPath)
	if err != nil {
		t.Fatal(err)
	}

	cfg.OpenPGP.Identities = []config.OpenPGPIdentity{{Sender: "alice@example.com", SigningKey: "missing.asc", Signing: "required"}}

	err = cfg.Save()
	if err != nil {
		t.Fatal(err)
	}

	output := filepath.Join(directory, "publication")

	_, err = Publish(configPath, output)
	if err == nil {
		t.Fatal("Publish() with missing source key succeeded")
	}

	_, statErr := os.Lstat(output)
	if !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("failed Publish() left target: %v", statErr)
	}
}
