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

const (
	hashMemory  = 19 * 1024
	hashTime    = 2
	hashThreads = 1

	saltLength = 16
	keyLength  = 32
)

var ErrInvalidHash = errors.New("malformed argon2id hash")

var encoding = base64.RawStdEncoding

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
	parts := strings.Split(hash, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return false, ErrInvalidHash
	}

	var version int

	_, err := fmt.Sscanf(parts[2], "v=%d", &version)
	if err != nil || version != argon2.Version {
		return false, ErrInvalidHash
	}

	if err := ValidatePHC(hash); err != nil {
		return false, err
	}

	memory, iterations, threads, err := parameters(parts[3])
	if err != nil {
		return false, err
	}

	salt, err := encoding.DecodeString(parts[4])
	if err != nil {
		return false, ErrInvalidHash
	}

	expected, err := encoding.DecodeString(parts[5])
	if err != nil || len(expected) == 0 {
		return false, ErrInvalidHash
	}

	key := argon2.IDKey([]byte(password), salt, iterations, memory, threads, uint32(len(expected)))

	return subtle.ConstantTimeCompare(key, expected) == 1, nil
}

// Waste burns a comparable amount of work for unknown users so that response
// timing does not disclose which usernames exist.
func Waste() {
	argon2.IDKey([]byte("outboxd"), make([]byte, saltLength), hashTime, hashMemory, hashThreads, keyLength)
}

const (
	maxMemory     = 1 << 30 // 1 GiB
	maxIterations = 100
	maxThreads    = 16
	maxSaltLen    = 64
	maxKeyLen     = 64
)

// ValidatePHC checks an Argon2id PHC string without deriving a key, enforcing
// bounds so hostile parameters cannot exhaust memory at authentication time.
func ValidatePHC(hash string) error {
	parts := strings.Split(hash, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return ErrInvalidHash
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return ErrInvalidHash
	}
	memory, iterations, threads, err := parameters(parts[3])
	if err != nil {
		return err
	}
	if memory == 0 || memory > maxMemory {
		return fmt.Errorf("%w: memory out of range", ErrInvalidHash)
	}
	if iterations == 0 || iterations > maxIterations {
		return fmt.Errorf("%w: iterations out of range", ErrInvalidHash)
	}
	if threads == 0 || threads > maxThreads {
		return fmt.Errorf("%w: parallelism out of range", ErrInvalidHash)
	}
	salt, err := encoding.DecodeString(parts[4])
	if err != nil || len(salt) == 0 || len(salt) > maxSaltLen {
		return fmt.Errorf("%w: salt size", ErrInvalidHash)
	}
	expected, err := encoding.DecodeString(parts[5])
	if err != nil || len(expected) == 0 || len(expected) > maxKeyLen {
		return fmt.Errorf("%w: output size", ErrInvalidHash)
	}
	return nil
}

func parameters(value string) (memory uint32, iterations uint32, threads uint8, err error) {
	for pair := range strings.SplitSeq(value, ",") {
		key, raw, ok := strings.Cut(pair, "=")
		if !ok {
			return 0, 0, 0, ErrInvalidHash
		}

		number, parseErr := strconv.ParseUint(raw, 10, 32)
		if parseErr != nil {
			return 0, 0, 0, ErrInvalidHash
		}

		switch key {
		case "m":
			memory = uint32(number)
		case "t":
			iterations = uint32(number)
		case "p":
			threads = uint8(number)
		default:
			return 0, 0, 0, ErrInvalidHash
		}
	}

	if memory == 0 || iterations == 0 || threads == 0 {
		return 0, 0, 0, ErrInvalidHash
	}

	return memory, iterations, threads, nil
}
