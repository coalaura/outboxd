package openpgp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"mime"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pgp "github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/ProtonMail/go-crypto/openpgp/s2k"
	"github.com/coalaura/outboxd/internal/config"
)

func testSigners(t *testing.T, sender string) (*Signers, *pgp.Entity) {
	t.Helper()

	entity, err := pgp.NewEntity("Alice", "", sender, &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA})
	if err != nil {
		t.Fatal(err)
	}

	return &Signers{
		identities: map[string]*identity{sender: {entity: entity, gate: make(chan struct{}, 1)}},
		maximum:    config.MaxMessageBytes,
	}, entity
}

func TestSignProducesVerifiableRFC3156Message(t *testing.T) {
	signers, entity := testSigners(t, "alice@example.com")
	message := []byte("From: Alice <alice@example.com>\r\nTo: Bob <bob@example.net>\r\nSubject: signed\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\nHello, J\xc3\xb6rg!\r\n")

	signed, ok, err := signers.Sign(context.Background(), "alice@example.com", message)
	if err != nil {
		t.Fatal(err)
	}

	if !ok {
		t.Fatal("message was not signed")
	}

	if bytes.Contains(signed, []byte{0xc3}) {
		t.Fatal("signed message is not 7-bit safe")
	}

	if !bytes.Contains(signed, []byte("Content-Transfer-Encoding: quoted-printable\r\n")) {
		t.Fatal("8-bit leaf was not converted to quoted-printable")
	}

	if !bytes.Contains(signed, []byte("-----BEGIN PGP SIGNATURE-----\r\n")) {
		t.Fatal("signature has the wrong armor type or line endings")
	}

	headerEnd := bytes.Index(signed, []byte("\r\n\r\n"))
	contentType := headerValue(signed[:headerEnd+2], "content-type")

	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil || mediaType != "multipart/signed" || params["protocol"] != "application/pgp-signature" || params["micalg"] != "pgp-sha256" {
		t.Fatalf("invalid multipart/signed Content-Type %q: %v", contentType, err)
	}

	boundary := []byte("--" + params["boundary"])

	firstStart := bytes.Index(signed[headerEnd+4:], boundary)
	firstStart += headerEnd + 4 + len(boundary) + 2

	second := bytes.Index(signed[firstStart:], append([]byte("\r\n"), boundary...))
	if second < 0 {
		t.Fatal("second MIME boundary not found")
	}

	firstPart := signed[firstStart : firstStart+second+2]

	sigStart := bytes.Index(signed[firstStart+second:], []byte("-----BEGIN PGP SIGNATURE-----"))
	if sigStart < 0 {
		t.Fatal("signature body not found")
	}

	sigStart += firstStart + second

	sigEnd := bytes.Index(signed[sigStart:], []byte("-----END PGP SIGNATURE-----"))
	sigEnd += sigStart + len("-----END PGP SIGNATURE-----")

	_, err = pgp.CheckArmoredDetachedSignature(pgp.EntityList{entity}, bytes.NewReader(firstPart), bytes.NewReader(signed[sigStart:sigEnd]), nil)
	if err != nil {
		t.Fatalf("detached signature does not verify over emitted first part: %v", err)
	}
}

func TestSignLeavesUnconfiguredSenderUnchanged(t *testing.T) {
	signers, _ := testSigners(t, "alice@example.com")

	message := []byte("From: bob@example.net\r\n\r\nhello\r\n")

	signed, ok, err := signers.Sign(context.Background(), "bob@example.net", message)
	if err != nil || ok || !bytes.Equal(signed, message) {
		t.Fatalf("Sign() = signed %v, err %v, data %q", ok, err, signed)
	}
}

func TestSignAcceptsOrdinaryMessageWithoutContentType(t *testing.T) {
	signers, _ := testSigners(t, "alice@example.com")

	message := []byte("From: alice@example.com\r\nSubject: plain\r\n\r\nordinary text\r\n")

	signed, ok, err := signers.Sign(context.Background(), "alice@example.com", message)
	if err != nil || !ok {
		t.Fatalf("Sign() = signed %v, err %v", ok, err)
	}

	if !bytes.Contains(signed, []byte("\r\n\r\nordinary text\r\n")) {
		t.Fatalf("signed message does not preserve default text/plain entity:\n%s", signed)
	}
}

func TestSignReportsExpansionBeyondMaximum(t *testing.T) {
	signers, _ := testSigners(t, "alice@example.com")

	message := []byte("From: alice@example.com\r\n\r\nhello\r\n")

	signers.maximum = int64(len(message) + 1)

	_, _, err := signers.Sign(context.Background(), "alice@example.com", message)
	if !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("Sign() error = %v", err)
	}
}

func TestCanonicalizeNestedMultipart(t *testing.T) {
	entity := []byte("Content-Type: multipart/alternative; boundary=x\r\n\r\npreamble\r\n--x\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\nh\xc3\xa9llo\r\n--x\r\nContent-Type: text/html\r\nContent-Transfer-Encoding: base64\r\n\r\naGk=\r\n--x--\r\nepilogue")

	canonical, err := canonicalizeEntity(entity, config.MaxMessageBytes)
	if err != nil {
		t.Fatal(err)
	}

	if !isSevenBit(canonical) || !bytes.Contains(canonical, []byte("h=C3=A9llo")) || !bytes.Contains(canonical, []byte("aGk=")) {
		t.Fatalf("unexpected canonical entity:\n%s", canonical)
	}
}

func TestCanonicalizeUsesDefaultContentType(t *testing.T) {
	entity := []byte("Content-Transfer-Encoding: 8bit\r\n\r\nh\xc3\xa9llo\r\n")

	canonical, err := canonicalizeEntity(entity, config.MaxMessageBytes)
	if err != nil {
		t.Fatal(err)
	}

	if !isSevenBit(canonical) || !bytes.Contains(canonical, []byte("h=C3=A9llo")) {
		t.Fatalf("unexpected canonical entity:\n%s", canonical)
	}
}

func TestCanonicalizeValidatesContentTransferEncodingBeforeFastPaths(t *testing.T) {
	tests := []struct {
		name   string
		entity string
		want   string
	}{
		{name: "leaf unsupported seven bit", entity: "Content-Transfer-Encoding: x-unknown\r\n\r\nhello\r\n", want: "unsupported MIME"},
		{name: "leaf empty", entity: "Content-Transfer-Encoding:\r\n\r\nhello\r\n", want: "Encoding is empty"},
		{name: "leaf duplicate", entity: "Content-Transfer-Encoding: 7bit\r\nContent-Transfer-Encoding: 8bit\r\n\r\nhello\r\n", want: "duplicate Content-Transfer-Encoding"},
		{name: "multipart encoded", entity: "Content-Type: multipart/mixed; boundary=x\r\nContent-Transfer-Encoding: base64\r\n\r\n--x--\r\n", want: "unsupported multipart MIME"},
		{name: "multipart duplicate", entity: "Content-Type: multipart/mixed; boundary=x\r\nContent-Transfer-Encoding: 7bit\r\nContent-Transfer-Encoding: 7bit\r\n\r\n--x--\r\n", want: "duplicate Content-Transfer-Encoding"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := canonicalizeEntity([]byte(test.entity), config.MaxMessageBytes)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("canonicalizeEntity() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestCanonicalizeContentTransferEncodingMatrix(t *testing.T) {
	leafEncodings := map[string]string{
		"":                 "",
		"7bit":             "7bit",
		"8bit":             "7bit",
		"binary":           "7bit",
		"base64":           "base64",
		"quoted-printable": "quoted-printable",
	}

	for encoding, expected := range leafEncodings {
		head := ""

		if encoding != "" {
			head = "Content-Transfer-Encoding: " + encoding + "\r\n"
		}

		canonical, err := canonicalizeEntity([]byte(head+"\r\nhello\r\n"), config.MaxMessageBytes)
		if err != nil {
			t.Errorf("leaf encoding %q rejected: %v", encoding, err)

			continue
		}

		canonicalHead := canonical[:bytes.Index(canonical, []byte("\r\n\r\n"))+2]
		if got := headerValue(canonicalHead, "content-transfer-encoding"); got != expected {
			t.Errorf("leaf encoding %q canonicalized to %q, want %q", encoding, got, expected)
		}
	}

	multipartEncodings := map[string]string{"": "", "7bit": "7bit", "8bit": "7bit", "binary": "7bit"}

	for encoding, expected := range multipartEncodings {
		head := "Content-Type: multipart/mixed; boundary=x\r\n"

		if encoding != "" {
			head += "Content-Transfer-Encoding: " + encoding + "\r\n"
		}

		canonical, err := canonicalizeEntity([]byte(head+"\r\n--x--\r\n"), config.MaxMessageBytes)
		if err != nil {
			t.Errorf("multipart encoding %q rejected: %v", encoding, err)

			continue
		}

		canonicalHead := canonical[:bytes.Index(canonical, []byte("\r\n\r\n"))+2]
		if got := headerValue(canonicalHead, "content-transfer-encoding"); got != expected {
			t.Errorf("multipart encoding %q canonicalized to %q, want %q", encoding, got, expected)
		}
	}
}

func TestCanonicalizeRejectsExcessiveMultipartNesting(t *testing.T) {
	entity := []byte("\r\ntext\r\n")

	for depth := 0; depth <= maxMultipartDepth; depth++ {
		boundary := fmt.Sprintf("boundary-%d", depth)

		entity = []byte(fmt.Sprintf("Content-Type: multipart/mixed; boundary=%s\r\n\r\n--%s\r\n%s--%s--\r\n", boundary, boundary, entity, boundary))
	}

	_, err := canonicalizeEntity(entity, config.MaxMessageBytes)
	if err == nil || !strings.Contains(err.Error(), "nesting exceeds") {
		t.Fatalf("canonicalizeEntity() error = %v", err)
	}
}

func TestSignCancellationWhileWaitingForSigner(t *testing.T) {
	signers, _ := testSigners(t, "alice@example.com")

	configured := signers.identities["alice@example.com"]

	configured.gate <- struct{}{}

	defer func() {
		<-configured.gate
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	started := time.Now()

	_, _, err := signers.Sign(ctx, "alice@example.com", []byte("From: alice@example.com\r\n\r\nhello\r\n"))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Sign() error = %v", err)
	}

	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("Sign() cancellation took %v", elapsed)
	}
}

func TestCanonicalizeHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := canonicalizeEntityContext(ctx, []byte("\r\nhello\r\n"), config.MaxMessageBytes, 0)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canonicalizeEntityContext() error = %v", err)
	}
}

func TestCanonicalizeExpansionReportsMessageTooLarge(t *testing.T) {
	_, err := canonicalizeEntity([]byte("Content-Transfer-Encoding: 8bit\r\n\r\n\xff\r\n"), 45)
	if !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("canonicalizeEntity() error = %v, want ErrMessageTooLarge", err)
	}
}

func TestLoadValidatesIdentityAndPrivateFile(t *testing.T) {
	dir := t.TempDir()

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
	if err != nil {
		t.Fatal(err)
	}

	err = armored.Close()
	if err != nil {
		t.Fatal(err)
	}

	keyPath := filepath.Join(dir, "alice.asc")

	err = os.WriteFile(keyPath, private.Bytes(), 0600)
	if err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{Server: config.Server{DataDirectory: dir, MaxMessageBytes: 1 << 20}, OpenPGP: config.OpenPGP{Identities: []config.OpenPGPIdentity{{Sender: "alice@example.com", SigningKey: "alice.asc", Signing: "required"}}}}

	_, err = Load(cfg)
	if err != nil {
		t.Fatal(err)
	}

	cfg.OpenPGP.Identities[0].Sender = "bob@example.com"

	_, err = Load(cfg)
	if err == nil || !strings.Contains(err.Error(), "not present") {
		t.Fatalf("wrong-identity Load() error = %v", err)
	}
}

func TestLoadEncryptedKeyPassphraseFile(t *testing.T) {
	dir := t.TempDir()

	entity, err := pgp.NewEntity("Alice", "", "alice@example.com", &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA})
	if err != nil {
		t.Fatal(err)
	}

	err = entity.EncryptPrivateKeys([]byte("correct horse battery staple"), nil)
	if err != nil {
		t.Fatal(err)
	}

	var private bytes.Buffer

	err = entity.SerializePrivateWithoutSigning(&private, nil)
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile(filepath.Join(dir, "alice.pgp"), private.Bytes(), 0600)
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile(filepath.Join(dir, "alice.pass"), []byte("correct horse battery staple\r\n"), 0600)
	if err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{Server: config.Server{DataDirectory: dir, MaxMessageBytes: 1 << 20}, OpenPGP: config.OpenPGP{Identities: []config.OpenPGPIdentity{{Sender: "alice@example.com", SigningKey: "alice.pgp", PassphraseFile: "alice.pass", Signing: "required"}}}}

	_, err = Load(cfg)
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile(filepath.Join(dir, "alice.pass"), []byte("wrong\n"), 0600)
	if err != nil {
		t.Fatal(err)
	}

	_, err = Load(cfg)
	if err == nil || !strings.Contains(err.Error(), "decrypt") {
		t.Fatalf("wrong-passphrase Load() error = %v", err)
	}
}

func TestValidatePrivateComponentsRejectsMixedEncryption(t *testing.T) {
	encrypted, err := pgp.NewEntity("Alice", "", "alice@example.com", &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA})
	if err != nil {
		t.Fatal(err)
	}

	err = encrypted.EncryptPrivateKeys([]byte("passphrase"), &packet.Config{S2KConfig: &s2k.Config{S2KMode: s2k.SaltedS2K, PassphraseIsHighEntropy: true}})
	if err != nil {
		t.Fatal(err)
	}

	plain, err := pgp.NewEntity("Bob", "", "bob@example.com", &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA})
	if err != nil {
		t.Fatal(err)
	}

	encrypted.Subkeys[0].PrivateKey = plain.Subkeys[0].PrivateKey

	_, err = validatePrivateComponents(encrypted, true)
	if err == nil || !strings.Contains(err.Error(), "mixed encrypted and unencrypted") {
		t.Fatalf("validatePrivateComponents() error = %v", err)
	}
}
