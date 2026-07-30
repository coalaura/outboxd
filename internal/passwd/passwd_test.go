package passwd

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
)

func TestValidatePHCBounds(t *testing.T) {
	// Valid default-shaped hash
	ok, err := Hash("secret")
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidatePHC(ok); err != nil {
		t.Fatal(err)
	}

	// Huge memory rejected
	huge := fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=2,p=1$AAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		argon2.Version, (1<<30)+1,
	)
	// Fix base64 lengths — salt 12 bytes = 16 raw b64? 16 zero bytes visualized
	salt := encoding.EncodeToString(make([]byte, 16))
	key := encoding.EncodeToString(make([]byte, 32))
	huge = fmt.Sprintf("$argon2id$v=%d$m=%d,t=2,p=1$%s$%s", argon2.Version, (1<<30)+1, salt, key)
	if err := ValidatePHC(huge); err == nil {
		t.Fatal("expected huge memory rejection")
	} else if !errors.Is(err, ErrInvalidHash) && !strings.Contains(err.Error(), "memory") {
		t.Fatalf("unexpected error: %v", err)
	}

	// Huge iterations
	iters := fmt.Sprintf("$argon2id$v=%d$m=19456,t=%d,p=1$%s$%s", argon2.Version, maxIterations+1, salt, key)
	if err := ValidatePHC(iters); err == nil {
		t.Fatal("expected iterations rejection")
	}

	// Huge threads
	thr := fmt.Sprintf("$argon2id$v=%d$m=19456,t=2,p=%d$%s$%s", argon2.Version, maxThreads+1, salt, key)
	if err := ValidatePHC(thr); err == nil {
		t.Fatal("expected threads rejection")
	}

	// Bad algorithm
	if err := ValidatePHC("$argon2i$v=19$m=8,t=1,p=1$aa$bb"); err == nil {
		t.Fatal("argon2i rejected")
	}

	// Empty
	if err := ValidatePHC(""); err == nil {
		t.Fatal("empty")
	}
}

func TestVerifyRejectsHostileBeforeDerive(t *testing.T) {
	salt := encoding.EncodeToString(make([]byte, 16))
	key := encoding.EncodeToString(make([]byte, 32))
	huge := fmt.Sprintf("$argon2id$v=%d$m=%d,t=2,p=1$%s$%s", argon2.Version, (1<<30)+1, salt, key)
	ok, err := Verify(huge, "pw")
	if ok || err == nil {
		t.Fatalf("Verify must reject hostile params, ok=%v err=%v", ok, err)
	}
}
