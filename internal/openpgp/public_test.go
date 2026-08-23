package openpgp

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"

	pgp "github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

func TestPublicIdentityMinimizesTransferableKey(t *testing.T) {
	entity, err := pgp.NewEntity("Alice", "", "alice@example.com", &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA})
	if err != nil {
		t.Fatal(err)
	}

	err = entity.AddUserId("Bob", "", "bob@example.com", &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA})
	if err != nil {
		t.Fatal(err)
	}

	public, err := publicIdentity(entity, "alice@example.com")
	if err != nil {
		t.Fatal(err)
	}

	wantFingerprint := strings.ToUpper(hex.EncodeToString(entity.PrimaryKey.Fingerprint))
	if public.Sender != "alice@example.com" || public.Fingerprint != wantFingerprint {
		t.Fatalf("public identity = %+v", public)
	}

	entities, err := pgp.ReadKeyRing(bytes.NewReader(public.Key))
	if err != nil {
		t.Fatal(err)
	}

	if len(entities) != 1 {
		t.Fatalf("parsed entities = %d", len(entities))
	}

	parsed := entities[0]
	if parsed.PrivateKey != nil {
		t.Fatal("minimized key contains a private primary key")
	}

	if len(parsed.Identities) != 1 || parsed.Identities["Alice <alice@example.com>"] == nil {
		t.Fatalf("minimized identities = %#v", parsed.Identities)
	}

	if len(parsed.Subkeys) != len(entity.Subkeys) {
		t.Fatalf("minimized subkeys = %d, want %d", len(parsed.Subkeys), len(entity.Subkeys))
	}

	for _, subkey := range parsed.Subkeys {
		if subkey.PrivateKey != nil {
			t.Fatal("minimized key contains a private subkey")
		}
	}

	reader := bytes.NewReader(public.Key)

	for {
		value, err := packet.Read(reader)
		if errors.Is(err, io.EOF) {
			break
		}

		if err != nil {
			t.Fatal(err)
		}

		if _, private := value.(*packet.PrivateKey); private {
			t.Fatalf("minimized key contains private packet %T", value)
		}
	}
}

func TestPublicIdentityRejectsAmbiguousSender(t *testing.T) {
	entity, err := pgp.NewEntity("Alice", "", "alice@example.com", &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA})
	if err != nil {
		t.Fatal(err)
	}

	err = entity.AddUserId("Alias", "", "alice@example.com", &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA})
	if err != nil {
		t.Fatal(err)
	}

	_, err = publicIdentity(entity, "alice@example.com")
	if err == nil || !strings.Contains(err.Error(), "multiple") {
		t.Fatalf("publicIdentity() error = %v", err)
	}
}

func TestAutocryptFieldIsFoldedAndRequiresEncryptionKey(t *testing.T) {
	entity, err := pgp.NewEntity("Alice", "", "alice@example.com", &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA})
	if err != nil {
		t.Fatal(err)
	}

	public, err := publicIdentity(entity, "alice@example.com")
	if err != nil {
		t.Fatal(err)
	}

	field, err := autocryptField(public)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.HasPrefix(field, []byte("Autocrypt: addr=alice@example.com; keydata=")) || !bytes.HasSuffix(field, []byte("\r\n")) {
		t.Fatalf("invalid Autocrypt field %q", field)
	}

	if len(field) > maxAutocryptFieldBytes {
		t.Fatalf("Autocrypt field length = %d", len(field))
	}

	for _, line := range bytes.Split(bytes.TrimSuffix(field, []byte("\r\n")), []byte("\r\n")) {
		if len(line) > 998 {
			t.Fatalf("Autocrypt physical line length = %d", len(line))
		}
	}
}

func TestWKDHashKnownVector(t *testing.T) {
	if got := wkdHash("test"); got != "iffe93qcsgp4c8ncbb378rxjo6cn9q6u" {
		t.Fatalf("wkdHash(test) = %q", got)
	}

	if got := wkdLocalPart("Alice-Ä"); got != "alice-Ä" {
		t.Fatalf("wkdLocalPart() = %q", got)
	}
}

func TestOpenPGPKeyOwnerPreservesLocalPartCaseAndNormalizesUnicode(t *testing.T) {
	upper, err := OpenPGPKeyOwner("Alice@EXAMPLE.com")
	if err != nil {
		t.Fatal(err)
	}

	lower, err := OpenPGPKeyOwner("alice@example.com")
	if err != nil {
		t.Fatal(err)
	}

	if upper != "3bc51062973c458d5a6f2d8d64a023246354ad7e064b1e4e009ec8a0._openpgpkey.example.com." {
		t.Fatalf("OpenPGPKeyOwner(Alice) = %q", upper)
	}

	if upper == lower {
		t.Fatal("OpenPGPKeyOwner() folded local-part case")
	}

	composed, err := OpenPGPKeyOwner("é@example.com")
	if err != nil {
		t.Fatal(err)
	}

	decomposed, err := OpenPGPKeyOwner("e\u0301@example.com")
	if err != nil {
		t.Fatal(err)
	}

	if composed != decomposed {
		t.Fatalf("Unicode-equivalent owners differ: %q != %q", composed, decomposed)
	}

	international, err := OpenPGPKeyOwner("alice@bücher.example")
	if err != nil {
		t.Fatal(err)
	}

	if !strings.HasSuffix(international, "._openpgpkey.xn--bcher-kva.example.") {
		t.Fatalf("internationalized owner domain = %q", international)
	}

	_, err = OpenPGPKeyOwner("alice@[127.0.0.1]")
	if err == nil {
		t.Fatal("OpenPGPKeyOwner() accepted an address-literal domain")
	}
}
