package passwd

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Memory is measured in KiB.
const (
	hashMemory  = 19 * 1024 // 19 MiB in KiB
	hashTime    = 2
	hashThreads = 1

	saltLength = 16
	keyLength  = 32
)

var ErrInvalidHash = errors.New("malformed argon2id hash")

var encoding = base64.RawStdEncoding

// PHCParams holds strict, validated parameters for Argon2id. Memory is in KiB.
type PHCParams struct {
	Memory     uint32
	Iterations uint32
	Threads    uint8
	Salt       []byte
	Key        []byte
}

// Hash derives an Argon2id hash in PHC string format.
func Hash(password string) (string, error) {
	salt := make([]byte, saltLength)

	_, err := rand.Read(salt)
	if err != nil {
		return "", err
	}

	key := argon2.IDKey([]byte(password), salt, hashTime, hashMemory, hashThreads, keyLength)

	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, hashMemory, hashTime, hashThreads,
		encoding.EncodeToString(salt), encoding.EncodeToString(key),
	), nil
}

// Verify compares a password against a PHC formatted Argon2id hash.
func Verify(hash, password string) (bool, error) {
	p, err := parsePHC(hash)
	if err != nil {
		return false, err
	}

	key := argon2.IDKey([]byte(password), p.Salt, p.Iterations, p.Memory, p.Threads, uint32(len(p.Key)))

	return subtle.ConstantTimeCompare(key, p.Key) == 1, nil
}

// Waste burns a comparable amount of work for unknown users so that response
// timing does not disclose which usernames exist.
func Waste() {
	argon2.IDKey([]byte("outboxd"), make([]byte, saltLength), hashTime, hashMemory, hashThreads, keyLength)
}

const (
	// Bound the entire PHC string before field work.
	maxPHCLength = 512
)

// maxEncodedLen is the maximum base64.RawStdEncoding length for n decoded bytes.
func maxEncodedLen(n int) int {
	// raw standard base64: 4 * ceil(n/3) without padding, but EncodeLen is exact.
	return encoding.EncodedLen(n)
}

// ValidatePHC checks an Argon2id PHC string without deriving a key, enforcing
// bounds so hostile parameters cannot exhaust memory at authentication time.
func ValidatePHC(hash string) error {
	_, err := parsePHC(hash)
	return err
}

func parsePHC(hash string) (*PHCParams, error) {
	if hash == "" || len(hash) > maxPHCLength {
		return nil, ErrInvalidHash
	}

	parts := strings.Split(hash, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return nil, ErrInvalidHash
	}

	expectedVersion := fmt.Sprintf("v=%d", argon2.Version)
	if parts[2] != expectedVersion {
		return nil, ErrInvalidHash
	}

	// Bound encoded salt/key before any base64 decode work.
	if len(parts[4]) > maxEncodedLen(saltLength) {
		return nil, fmt.Errorf("%w: salt size", ErrInvalidHash)
	}
	if len(parts[5]) > maxEncodedLen(keyLength) {
		return nil, fmt.Errorf("%w: output size", ErrInvalidHash)
	}

	canonical := fmt.Sprintf("m=%d,t=%d,p=%d", hashMemory, hashTime, hashThreads)
	if parts[3] != canonical {
		return nil, fmt.Errorf("%w: non-canonical parameters", ErrInvalidHash)
	}

	salt, err := encoding.DecodeString(parts[4])
	if err != nil || len(salt) != saltLength {
		return nil, fmt.Errorf("%w: salt size", ErrInvalidHash)
	}

	expected, err := encoding.DecodeString(parts[5])
	if err != nil || len(expected) != keyLength {
		return nil, fmt.Errorf("%w: output size", ErrInvalidHash)
	}

	return &PHCParams{
		Memory:     hashMemory,
		Iterations: hashTime,
		Threads:    hashThreads,
		Salt:       salt,
		Key:        expected,
	}, nil
}
