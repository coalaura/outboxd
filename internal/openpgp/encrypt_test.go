package openpgp

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pgp "github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/coalaura/outboxd/internal/config"
)

func TestLoadRecipientsEncryptsRFC3156Message(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "recipients")

	err := os.Mkdir(directory, 0700)
	if err != nil {
		t.Fatal(err)
	}

	entity, err := pgp.NewEntity("Bob", "", "bob@exämple.NET", &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA})
	if err != nil {
		t.Fatal(err)
	}

	var public bytes.Buffer

	armored, err := armor.Encode(&public, pgp.PublicKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}

	err = entity.Serialize(armored)
	if err != nil {
		t.Fatal(err)
	}

	err = armored.Close()
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile(filepath.Join(directory, "bob.asc"), public.Bytes(), 0600)
	if err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{
		Server: config.Server{DataDirectory: filepath.Dir(directory), MaxMessageBytes: 1 << 20},
		OpenPGP: config.OpenPGP{
			RecipientKeysDirectory: "recipients",
			RequireEncryptionFor:   []string{"bob@xn--exmple-cua.net"},
		},
	}

	recipients, err := LoadRecipients(cfg)
	if err != nil {
		t.Fatal(err)
	}

	keyID, found, err := recipients.KeyID("bob@EXÄMPLE.NET")
	if err != nil || !found {
		t.Fatalf("KeyID() = found %v, err %v", found, err)
	}

	encryptionKey, ok := entity.EncryptionKey(time.Now())
	if !ok {
		t.Fatal("generated entity has no encryption key")
	}

	wantKeyID := fmt.Sprintf("%X", encryptionKey.PublicKey.Fingerprint)
	if keyID != wantKeyID {
		t.Fatalf("KeyID() = %q, want encryption key fingerprint %q", keyID, wantKeyID)
	}

	_, found, err = recipients.KeyID("Bob@xn--exmple-cua.net")
	if err != nil || found {
		t.Fatalf("case-sensitive local KeyID() = found %v, err %v", found, err)
	}

	message := []byte("From: alice@example.com\r\nTo: bob@xn--exmple-cua.net\r\nSubject: secret\r\nContent-Type: text/plain\r\n\r\nhello\r\n")

	encrypted, ok, err := recipients.Encrypt(context.Background(), "bob@xn--exmple-cua.net", keyID, message)
	if err != nil || !ok {
		t.Fatalf("Encrypt() = encrypted %v, err %v", ok, err)
	}

	if bytes.Contains(encrypted, []byte("\r\nhello\r\n")) || !bytes.Contains(encrypted, []byte("multipart/encrypted")) {
		t.Fatalf("unexpected encrypted message:\n%s", encrypted)
	}

	start := bytes.Index(encrypted, []byte("-----BEGIN PGP MESSAGE-----"))
	end := bytes.Index(encrypted[start:], []byte("-----END PGP MESSAGE-----"))

	if start < 0 || end < 0 {
		t.Fatal("armored encrypted body not found")
	}

	end += start + len("-----END PGP MESSAGE-----")

	block, err := armor.Decode(bytes.NewReader(encrypted[start:end]))
	if err != nil {
		t.Fatal(err)
	}

	details, err := pgp.ReadMessage(block.Body, pgp.EntityList{entity}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	plaintext, err := io.ReadAll(details.UnverifiedBody)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Contains(plaintext, []byte("Content-Type: text/plain\r\n\r\nhello\r\n")) {
		t.Fatalf("decrypted MIME entity = %q", plaintext)
	}
}

func TestSupportedEncryptionAlgorithmRejectsElGamal(t *testing.T) {
	if supportedEncryptionAlgorithm(packet.PubKeyAlgoElGamal) {
		t.Fatal("ElGamal recipient key accepted")
	}
}

func TestLoadRecipientsRejectsPrivateMaterialAndMissingRequiredKey(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "recipients")

	err := os.Mkdir(directory, 0700)
	if err != nil {
		t.Fatal(err)
	}

	entity, err := pgp.NewEntity("Bob", "", "bob@example.net", &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA})
	if err != nil {
		t.Fatal(err)
	}

	var private bytes.Buffer

	err = entity.SerializePrivate(&private, nil)
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile(filepath.Join(directory, "bob.pgp"), private.Bytes(), 0600)
	if err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{Server: config.Server{DataDirectory: filepath.Dir(directory), MaxMessageBytes: 1 << 20}, OpenPGP: config.OpenPGP{RecipientKeysDirectory: "recipients"}}

	_, err = LoadRecipients(cfg)
	if err == nil || !strings.Contains(err.Error(), "private key material") {
		t.Fatalf("private LoadRecipients() error = %v", err)
	}

	err = os.Remove(filepath.Join(directory, "bob.pgp"))
	if err != nil {
		t.Fatal(err)
	}

	cfg.OpenPGP.RequireEncryptionFor = []string{"bob@example.net"}

	_, err = LoadRecipients(cfg)
	if err == nil || !strings.Contains(err.Error(), "no usable static key") {
		t.Fatalf("required LoadRecipients() error = %v", err)
	}
}
