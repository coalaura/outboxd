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

	memory, time, threads, err := parameters(parts[3])
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

	key := argon2.IDKey([]byte(password), salt, time, memory, threads, uint32(len(expected)))

	return subtle.ConstantTimeCompare(key, expected) == 1, nil
}

// Waste burns a comparable amount of work for unknown users so that response
// timing does not disclose which usernames exist.
func Waste() {
	argon2.IDKey([]byte("outboxd"), make([]byte, saltLength), hashTime, hashMemory, hashThreads, keyLength)
}

func parameters(value string) (memory uint32, time uint32, threads uint8, err error) {
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
			time = uint32(number)
		case "p":
			threads = uint8(number)
		default:
			return 0, 0, 0, ErrInvalidHash
		}
	}

	if memory == 0 || time == 0 || threads == 0 {
		return 0, 0, 0, ErrInvalidHash
	}

	return memory, time, threads, nil
}
