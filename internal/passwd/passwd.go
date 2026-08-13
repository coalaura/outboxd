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

	// Bound the entire PHC string before field work.
	maxPHCLength = 512

	migrationPrefix     = "{ARGON2ID}"
	maxMigrationMemory  = 128 * 1024
	maxMigrationTime    = 5
	maxMigrationThreads = 8
	maxMigrationSalt    = 64
	maxMigrationKey     = 64
)

var (
	ErrInvalidHash = errors.New("malformed argon2id hash")
	encoding       = base64.RawStdEncoding
)

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
		argon2.Version,
		hashMemory,
		hashTime,
		hashThreads,
		encoding.EncodeToString(salt),
		encoding.EncodeToString(key),
	), nil
}

// Verify compares a password against an outboxd or {ARGON2ID}-prefixed hash.
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

// maxEncodedLen is the maximum base64.RawStdEncoding length for n decoded bytes.
func maxEncodedLen(n int) int {
	// raw standard base64: 4 * ceil(n/3) without padding, but EncodeLen is exact.
	return encoding.EncodedLen(n)
}

// ValidatePHC checks an outboxd or {ARGON2ID}-prefixed Argon2id PHC string
// without deriving a key, enforcing bounds so hostile parameters cannot
// exhaust resources at authentication time.
func ValidatePHC(hash string) error {
	_, err := parsePHC(hash)
	return err
}

func parsePHC(hash string) (*PHCParams, error) {
	if hash == "" || len(hash) > maxPHCLength {
		return nil, ErrInvalidHash
	}

	var migration bool

	if len(hash) >= len(migrationPrefix) && strings.EqualFold(hash[:len(migrationPrefix)], migrationPrefix) {
		migration = true

		hash = hash[len(migrationPrefix):]
	}

	parts := strings.Split(hash, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return nil, ErrInvalidHash
	}

	expectedVersion := fmt.Sprintf("v=%d", argon2.Version)
	if parts[2] != expectedVersion {
		return nil, ErrInvalidHash
	}

	maxSalt := saltLength
	maxKey := keyLength

	if migration {
		maxSalt = maxMigrationSalt
		maxKey = maxMigrationKey
	}

	// Bound encoded salt/key before any base64 decode work.
	if len(parts[4]) > maxEncodedLen(maxSalt) {
		return nil, fmt.Errorf("%w: salt size", ErrInvalidHash)
	}

	if len(parts[5]) > maxEncodedLen(maxKey) {
		return nil, fmt.Errorf("%w: output size", ErrInvalidHash)
	}

	memory, iterations, threads, err := parseParams(parts[3], migration)
	if err != nil {
		return nil, err
	}

	salt, err := encoding.DecodeString(parts[4])
	if err != nil || len(salt) == 0 || len(salt) > maxSalt || (!migration && len(salt) != saltLength) {
		return nil, fmt.Errorf("%w: salt size", ErrInvalidHash)
	}

	expected, err := encoding.DecodeString(parts[5])
	if err != nil || len(expected) == 0 || len(expected) > maxKey || (!migration && len(expected) != keyLength) {
		return nil, fmt.Errorf("%w: output size", ErrInvalidHash)
	}

	return &PHCParams{
		Memory:     memory,
		Iterations: iterations,
		Threads:    threads,
		Salt:       salt,
		Key:        expected,
	}, nil
}

func parseParams(value string, migration bool) (uint32, uint32, uint8, error) {
	canonical := fmt.Sprintf("m=%d,t=%d,p=%d", hashMemory, hashTime, hashThreads)

	if !migration {
		if value != canonical {
			return 0, 0, 0, fmt.Errorf("%w: non-canonical parameters", ErrInvalidHash)
		}

		return hashMemory, hashTime, hashThreads, nil
	}

	var (
		memory     uint32
		iterations uint32
		threads    uint8
	)

	n, err := fmt.Sscanf(value, "m=%d,t=%d,p=%d", &memory, &iterations, &threads)
	if err != nil || n != 3 || value != fmt.Sprintf("m=%d,t=%d,p=%d", memory, iterations, threads) {
		return 0, 0, 0, fmt.Errorf("%w: parameters", ErrInvalidHash)
	}

	if memory < 8*uint32(threads) || memory > maxMigrationMemory || iterations == 0 || iterations > maxMigrationTime || threads == 0 || threads > maxMigrationThreads {
		return 0, 0, 0, fmt.Errorf("%w: parameters out of bounds", ErrInvalidHash)
	}

	return memory, iterations, threads, nil
}
