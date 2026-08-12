package queue

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

// idPattern accepts the envelope IDs this process generates and previously
// generated forms. Paths, separators and traversal sequences are rejected.
var idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,190}$`)

// ValidateID rejects path traversal and malformed identifiers.
func ValidateID(id string) error {
	if id == "" || !idPattern.MatchString(id) {
		return ErrInvalidID
	}

	if id == "." || id == ".." || strings.ContainsAny(id, `/\`) {
		return ErrInvalidID
	}

	if filepath.Base(id) != id || filepath.IsAbs(id) {
		return ErrInvalidID
	}

	clean := filepath.Clean(id)
	if clean != id {
		return ErrInvalidID
	}

	return nil
}

// DSNID returns the stable queue ID for one source-message incarnation and
// notification generation.
func DSNID(sourceID, incarnation string, generation uint64) string {
	sum := sha256.Sum256(fmt.Appendf(nil, "outboxd-dsn-v1\x00%s\x00%s\x00%d", sourceID, incarnation, generation))

	return fmt.Sprintf("dsn.%x", sum)
}

func newIncarnation() (string, error) {
	var token [16]byte

	_, err := rand.Read(token[:])
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(token[:]), nil
}
