package passwd

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
)

type phcCanonicalSizeCase struct {
	salt []byte
	key  []byte
}

func TestHashAndVerify(t *testing.T) {
	pw := "correct-horse-battery-staple"
	h, err := Hash(pw)
	if err != nil {
		t.Fatalf("Hash failed: %v", err)
	}

	err = ValidatePHC(h)
	if err != nil {
		t.Fatalf("ValidatePHC failed on generated hash: %v", err)
	}

	ok, err := Verify(h, pw)
	if err != nil || !ok {
		t.Fatalf("Verify failed: ok=%v err=%v", ok, err)
	}

	wrongOK, err := Verify(h, "wrong-password")
	if err != nil {
		t.Fatalf("Verify with wrong password returned error: %v", err)
	}

	if wrongOK {
		t.Fatal("Verify succeeded with wrong password")
	}
}

func TestValidatePHCBounds(t *testing.T) {
	salt := encoding.EncodeToString(make([]byte, 16))
	key := encoding.EncodeToString(make([]byte, 32))

	canonical := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, hashMemory, hashTime, hashThreads, salt, key)
	err := ValidatePHC(canonical)
	if err != nil {
		t.Fatalf("canonical parameters rejected: %v", err)
	}

	for _, params := range []string{
		"m=19457,t=2,p=1",
		"m=19456,t=3,p=1",
		"m=19456,t=2,p=2",
		"t=2,m=19456,p=1",
	} {

		h := fmt.Sprintf("$argon2id$v=%d$%s$%s$%s", argon2.Version, params, salt, key)
		err := ValidatePHC(h)
		if err == nil {
			t.Fatalf("non-canonical parameters %q accepted", params)
		}
	}

	// m=1073741824 (1 TiB in KiB) rejected without derivation.
	m1TiB := fmt.Sprintf("$argon2id$v=%d$m=1073741824,t=2,p=1$%s$%s", argon2.Version, salt, key)
	err = ValidatePHC(m1TiB)
	if err == nil {
		t.Fatal("expected m=1073741824 to be rejected")
	}

	// Old 256 MiB limit now rejected.
	m256 := fmt.Sprintf("$argon2id$v=%d$m=%d,t=2,p=1$%s$%s", argon2.Version, 256*1024, salt, key)
	err = ValidatePHC(m256)
	if err == nil {
		t.Fatal("expected old 256 MiB memory to be rejected")
	}

	// Duplicate parameters
	dupM := fmt.Sprintf("$argon2id$v=%d$m=1024,m=1024,t=2,p=1$%s$%s", argon2.Version, salt, key)
	err = ValidatePHC(dupM)
	if err == nil {
		t.Fatal("expected duplicate m to be rejected")
	}

	// Unknown parameters
	unknown := fmt.Sprintf("$argon2id$v=%d$m=1024,t=2,p=1,x=10$%s$%s", argon2.Version, salt, key)
	err = ValidatePHC(unknown)
	if err == nil {
		t.Fatal("expected unknown parameter x to be rejected")
	}

	// Missing parameters
	missingP := fmt.Sprintf("$argon2id$v=%d$m=1024,t=2$%s$%s", argon2.Version, salt, key)
	err = ValidatePHC(missingP)
	if err == nil {
		t.Fatal("expected missing p to be rejected")
	}

	// Trailing characters after version (v=19junk)
	junkV := fmt.Sprintf("$argon2id$v=19junk$m=1024,t=2,p=1$%s$%s", salt, key)
	err = ValidatePHC(junkV)
	if err == nil {
		t.Fatal("expected v=19junk to be rejected")
	}

	// Oversized salt (decoded 65 bytes) — rejected before decode via encoded length bound
	// when field is huge; 65-byte salt encoded is short enough to decode then reject.
	salt65 := encoding.EncodeToString(make([]byte, 65))
	overSalt := fmt.Sprintf("$argon2id$v=%d$m=1024,t=2,p=1$%s$%s", argon2.Version, salt65, key)
	err = ValidatePHC(overSalt)
	if err == nil {
		t.Fatal("expected oversized salt to be rejected")
	}

	// Extremely long salt field rejected before base64 decode.
	hugeSaltField := strings.Repeat("A", maxEncodedLen(saltLength)+1)
	hugeSalt := fmt.Sprintf("$argon2id$v=%d$m=1024,t=2,p=1$%s$%s", argon2.Version, hugeSaltField, key)
	err = ValidatePHC(hugeSalt)
	if err == nil {
		t.Fatal("expected huge encoded salt to be rejected before decode")
	}

	// Oversized output/key
	key65 := encoding.EncodeToString(make([]byte, 65))
	overKey := fmt.Sprintf("$argon2id$v=%d$m=1024,t=2,p=1$%s$%s", argon2.Version, salt, key65)
	err = ValidatePHC(overKey)
	if err == nil {
		t.Fatal("expected oversized key to be rejected")
	}

	hugeKeyField := strings.Repeat("A", maxEncodedLen(keyLength)+1)
	hugeKey := fmt.Sprintf("$argon2id$v=%d$m=1024,t=2,p=1$%s$%s", argon2.Version, salt, hugeKeyField)
	err = ValidatePHC(hugeKey)
	if err == nil {
		t.Fatal("expected huge encoded key to be rejected before decode")
	}

	// Invalid base64
	badB64 := fmt.Sprintf("$argon2id$v=%d$m=1024,t=2,p=1$!!!badb64!!!$%s", argon2.Version, key)
	err = ValidatePHC(badB64)
	if err == nil {
		t.Fatal("expected invalid base64 to be rejected")
	}

	// Very large decimal values without overflow or panic
	hugeDec := fmt.Sprintf("$argon2id$v=%d$m=99999999999999999999999,t=2,p=1$%s$%s", argon2.Version, salt, key)
	err = ValidatePHC(hugeDec)
	if err == nil {
		t.Fatal("expected huge decimal m to be rejected without panic")
	}

	// Total PHC length bound
	longPHC := "$argon2id$v=19$m=1024,t=2,p=1$" + strings.Repeat("A", maxPHCLength)
	err = ValidatePHC(longPHC)
	if err == nil {
		t.Fatal("expected total PHC length bound")
	}

	// Bad algorithm
	err = ValidatePHC("$argon2i$v=19$m=8,t=1,p=1$aa$bb")
	if err == nil {
		t.Fatal("argon2i rejected")
	}

	// Empty
	err = ValidatePHC("")
	if err == nil {
		t.Fatal("empty string rejected")
	}
}

func TestVerifyRejectsHostileBeforeDerive(t *testing.T) {
	salt := encoding.EncodeToString(make([]byte, 16))
	key := encoding.EncodeToString(make([]byte, 32))
	huge := fmt.Sprintf("$argon2id$v=%d$m=1073741824,t=2,p=1$%s$%s", argon2.Version, salt, key)
	ok, err := Verify(huge, "pw")
	if ok || err == nil {
		t.Fatalf("Verify must reject hostile params before derive, ok=%v err=%v", ok, err)
	}

	if !errors.Is(err, ErrInvalidHash) && !strings.Contains(err.Error(), "memory") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidatePHCRequiresCanonicalSizes(t *testing.T) {
	salt := encoding.EncodeToString(make([]byte, 16))
	key := encoding.EncodeToString(make([]byte, 32))
	params := fmt.Sprintf("m=%d,t=%d,p=%d", hashMemory, hashTime, hashThreads)

	for _, tc := range []phcCanonicalSizeCase{
		{make([]byte, saltLength-1), make([]byte, keyLength)},
		{make([]byte, saltLength+1), make([]byte, keyLength)},
		{make([]byte, saltLength), make([]byte, keyLength-1)},
		{make([]byte, saltLength), make([]byte, keyLength+1)},
	} {

		h := fmt.Sprintf("$argon2id$v=%d$%s$%s$%s", argon2.Version, params, encoding.EncodeToString(tc.salt), encoding.EncodeToString(tc.key))
		err := ValidatePHC(h)
		if err == nil {
			t.Fatalf("accepted salt=%d key=%d", len(tc.salt), len(tc.key))
		}
	}

	_ = salt
	_ = key
}
