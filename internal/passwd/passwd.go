package passwd

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
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

// Accepted extremes for stored PHC parameters.
// Memory is measured in KiB (1 KiB = 1024 bytes).
const (
	maxMemory     = 64 * 1024 // 64 MiB in KiB
	maxIterations = 10
	maxThreads    = 4
	minSaltLen    = 8
	maxSaltLen    = 64
	minKeyLen     = 16
	maxKeyLen     = 64

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
	if len(parts[4]) > maxEncodedLen(maxSaltLen) {
		return nil, fmt.Errorf("%w: salt size", ErrInvalidHash)
	}
	if len(parts[5]) > maxEncodedLen(maxKeyLen) {
		return nil, fmt.Errorf("%w: output size", ErrInvalidHash)
	}

	var (
		memory     uint32
		iterations uint32
		threads    uint8
		seenM      bool
		seenT      bool
		seenP      bool
	)

	for pair := range strings.SplitSeq(parts[3], ",") {
		key, raw, ok := strings.Cut(pair, "=")
		if !ok {
			return nil, ErrInvalidHash
		}

		// Parse into a wide type; validate before narrowing.
		val, parseErr := strconv.ParseUint(raw, 10, 64)
		if parseErr != nil {
			return nil, ErrInvalidHash
		}

		switch key {
		case "m":
			if seenM || val == 0 || val > maxMemory {
				return nil, fmt.Errorf("%w: memory out of range", ErrInvalidHash)
			}
			if val > uint64(^uint32(0)) {
				return nil, fmt.Errorf("%w: memory out of range", ErrInvalidHash)
			}
			memory = uint32(val)
			seenM = true
		case "t":
			if seenT || val == 0 || val > maxIterations {
				return nil, fmt.Errorf("%w: iterations out of range", ErrInvalidHash)
			}
			if val > uint64(^uint32(0)) {
				return nil, fmt.Errorf("%w: iterations out of range", ErrInvalidHash)
			}
			iterations = uint32(val)
			seenT = true
		case "p":
			if seenP || val == 0 || val > maxThreads {
				return nil, fmt.Errorf("%w: parallelism out of range", ErrInvalidHash)
			}
			if val > 255 {
				return nil, fmt.Errorf("%w: parallelism out of range", ErrInvalidHash)
			}
			threads = uint8(val)
			seenP = true
		default:
			return nil, ErrInvalidHash
		}
	}

	if !seenM || !seenT || !seenP {
		return nil, ErrInvalidHash
	}

	// Argon2 requires memory (KiB) >= 8 * parallelism.
	if uint64(memory) < 8*uint64(threads) {
		return nil, fmt.Errorf("%w: memory too small for parallelism", ErrInvalidHash)
	}

	salt, err := encoding.DecodeString(parts[4])
	if err != nil || len(salt) < minSaltLen || len(salt) > maxSaltLen {
		return nil, fmt.Errorf("%w: salt size", ErrInvalidHash)
	}

	expected, err := encoding.DecodeString(parts[5])
	if err != nil || len(expected) < minKeyLen || len(expected) > maxKeyLen {
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
