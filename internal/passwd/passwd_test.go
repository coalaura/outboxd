package passwd

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
)

func TestHashAndVerify(t *testing.T) {
	pw := "correct-horse-battery-staple"
	h, err := Hash(pw)
	if err != nil {
		t.Fatalf("Hash failed: %v", err)
	}

	if err := ValidatePHC(h); err != nil {
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

	// Memory just above 64 MiB (KiB units).
	mOver := fmt.Sprintf("$argon2id$v=%d$m=%d,t=2,p=1$%s$%s", argon2.Version, maxMemory+1, salt, key)
	if err := ValidatePHC(mOver); err == nil {
		t.Fatal("expected memory just above 64 MiB to be rejected")
	}

	// Valid max memory (64 * 1024 KiB = 64 MiB).
	mMax := fmt.Sprintf("$argon2id$v=%d$m=%d,t=2,p=1$%s$%s", argon2.Version, maxMemory, salt, key)
	if err := ValidatePHC(mMax); err != nil {
		t.Fatalf("expected m=%d to be valid, got: %v", maxMemory, err)
	}

	// Iterations at edge of accepted range.
	t10 := fmt.Sprintf("$argon2id$v=%d$m=19456,t=10,p=1$%s$%s", argon2.Version, salt, key)
	if err := ValidatePHC(t10); err != nil {
		t.Fatalf("t=10 must be accepted: %v", err)
	}
	t11 := fmt.Sprintf("$argon2id$v=%d$m=19456,t=11,p=1$%s$%s", argon2.Version, salt, key)
	if err := ValidatePHC(t11); err == nil {
		t.Fatal("t=11 must be rejected")
	}

	// Parallelism.
	p4 := fmt.Sprintf("$argon2id$v=%d$m=19456,t=2,p=4$%s$%s", argon2.Version, salt, key)
	if err := ValidatePHC(p4); err != nil {
		t.Fatalf("p=4 must be accepted: %v", err)
	}
	for _, p := range []int{5, 257, 272} {
		hp := fmt.Sprintf("$argon2id$v=%d$m=19456,t=2,p=%d$%s$%s", argon2.Version, p, salt, key)
		if err := ValidatePHC(hp); err == nil {
			t.Fatalf("expected p=%d to be rejected", p)
		}
	}

	// m=1073741824 (1 TiB in KiB) rejected without derivation.
	m1TiB := fmt.Sprintf("$argon2id$v=%d$m=1073741824,t=2,p=1$%s$%s", argon2.Version, salt, key)
	if err := ValidatePHC(m1TiB); err == nil {
		t.Fatal("expected m=1073741824 to be rejected")
	}
	// Old 256 MiB limit now rejected.
	m256 := fmt.Sprintf("$argon2id$v=%d$m=%d,t=2,p=1$%s$%s", argon2.Version, 256*1024, salt, key)
	if err := ValidatePHC(m256); err == nil {
		t.Fatal("expected old 256 MiB memory to be rejected")
	}

	// Duplicate parameters
	dupM := fmt.Sprintf("$argon2id$v=%d$m=1024,m=1024,t=2,p=1$%s$%s", argon2.Version, salt, key)
	if err := ValidatePHC(dupM); err == nil {
		t.Fatal("expected duplicate m to be rejected")
	}

	// Unknown parameters
	unknown := fmt.Sprintf("$argon2id$v=%d$m=1024,t=2,p=1,x=10$%s$%s", argon2.Version, salt, key)
	if err := ValidatePHC(unknown); err == nil {
		t.Fatal("expected unknown parameter x to be rejected")
	}

	// Missing parameters
	missingP := fmt.Sprintf("$argon2id$v=%d$m=1024,t=2$%s$%s", argon2.Version, salt, key)
	if err := ValidatePHC(missingP); err == nil {
		t.Fatal("expected missing p to be rejected")
	}

	// Trailing characters after version (v=19junk)
	junkV := fmt.Sprintf("$argon2id$v=19junk$m=1024,t=2,p=1$%s$%s", salt, key)
	if err := ValidatePHC(junkV); err == nil {
		t.Fatal("expected v=19junk to be rejected")
	}

	// Oversized salt (decoded 65 bytes) — rejected before decode via encoded length bound
	// when field is huge; 65-byte salt encoded is short enough to decode then reject.
	salt65 := encoding.EncodeToString(make([]byte, 65))
	overSalt := fmt.Sprintf("$argon2id$v=%d$m=1024,t=2,p=1$%s$%s", argon2.Version, salt65, key)
	if err := ValidatePHC(overSalt); err == nil {
		t.Fatal("expected oversized salt to be rejected")
	}

	// Extremely long salt field rejected before base64 decode.
	hugeSaltField := strings.Repeat("A", maxEncodedLen(maxSaltLen)+1)
	hugeSalt := fmt.Sprintf("$argon2id$v=%d$m=1024,t=2,p=1$%s$%s", argon2.Version, hugeSaltField, key)
	if err := ValidatePHC(hugeSalt); err == nil {
		t.Fatal("expected huge encoded salt to be rejected before decode")
	}

	// Oversized output/key
	key65 := encoding.EncodeToString(make([]byte, 65))
	overKey := fmt.Sprintf("$argon2id$v=%d$m=1024,t=2,p=1$%s$%s", argon2.Version, salt, key65)
	if err := ValidatePHC(overKey); err == nil {
		t.Fatal("expected oversized key to be rejected")
	}
	hugeKeyField := strings.Repeat("A", maxEncodedLen(maxKeyLen)+1)
	hugeKey := fmt.Sprintf("$argon2id$v=%d$m=1024,t=2,p=1$%s$%s", argon2.Version, salt, hugeKeyField)
	if err := ValidatePHC(hugeKey); err == nil {
		t.Fatal("expected huge encoded key to be rejected before decode")
	}

	// Invalid base64
	badB64 := fmt.Sprintf("$argon2id$v=%d$m=1024,t=2,p=1$!!!badb64!!!$%s", argon2.Version, key)
	if err := ValidatePHC(badB64); err == nil {
		t.Fatal("expected invalid base64 to be rejected")
	}

	// Very large decimal values without overflow or panic
	hugeDec := fmt.Sprintf("$argon2id$v=%d$m=99999999999999999999999,t=2,p=1$%s$%s", argon2.Version, salt, key)
	if err := ValidatePHC(hugeDec); err == nil {
		t.Fatal("expected huge decimal m to be rejected without panic")
	}

	// Total PHC length bound
	longPHC := "$argon2id$v=19$m=1024,t=2,p=1$" + strings.Repeat("A", maxPHCLength)
	if err := ValidatePHC(longPHC); err == nil {
		t.Fatal("expected total PHC length bound")
	}

	// Bad algorithm
	if err := ValidatePHC("$argon2i$v=19$m=8,t=1,p=1$aa$bb"); err == nil {
		t.Fatal("argon2i rejected")
	}

	// Empty
	if err := ValidatePHC(""); err == nil {
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

func TestValidatePHCMemoryParallelismRelation(t *testing.T) {
	salt := encoding.EncodeToString(make([]byte, 16))
	key := encoding.EncodeToString(make([]byte, 32))

	// m >= 8*p accepted at structural edges (no IDKey call for max profile).
	accept := []struct {
		m, p int
	}{
		{8, 1},
		{32, 4},
		{19456, 1},
	}
	for _, c := range accept {
		h := fmt.Sprintf("$argon2id$v=%d$m=%d,t=2,p=%d$%s$%s", argon2.Version, c.m, c.p, salt, key)
		if err := ValidatePHC(h); err != nil {
			t.Fatalf("m=%d p=%d should accept: %v", c.m, c.p, err)
		}
	}
	reject := []struct {
		m, p int
	}{
		{7, 1},
		{31, 4},
		{1, 4},
	}
	for _, c := range reject {
		h := fmt.Sprintf("$argon2id$v=%d$m=%d,t=2,p=%d$%s$%s", argon2.Version, c.m, c.p, salt, key)
		if err := ValidatePHC(h); err == nil {
			t.Fatalf("m=%d p=%d must reject", c.m, c.p)
		}
	}
	// Hostile relationship via Verify: ordinary error, no panic.
	bad := fmt.Sprintf("$argon2id$v=%d$m=1,t=2,p=4$%s$%s", argon2.Version, salt, key)
	ok, err := Verify(bad, "x")
	if ok || err == nil {
		t.Fatalf("Verify hostile relation ok=%v err=%v", ok, err)
	}
}
