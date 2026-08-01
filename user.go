package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/coalaura/outboxd/internal/config"
	"github.com/coalaura/outboxd/internal/passwd"
)

func user(configPath string, arguments []string) error {
	if len(arguments) < 2 || arguments[0] != "add" {
		return errors.New("usage: outboxd user add <username> [sender...]")
	}

	username := arguments[1]

	senders := arguments[2:]
	if len(senders) == 0 {
		if !strings.Contains(username, "@") {
			return errors.New("provide at least one allowed sender address")
		}

		senders = []string{username}
	}

	password, generated, err := password()
	if err != nil {
		return err
	}

	hash, err := passwd.Hash(password)
	if err != nil {
		return err
	}

	entry := config.User{
		Username:       username,
		PasswordHash:   hash,
		AllowedSenders: senders,
		Enabled:        true,
	}

	cfg, created, err := ensureConfig(configPath)
	if err != nil {
		return err
	}

	if created {
		fmt.Fprintf(os.Stderr, "created default config at %q\n", cfg.Path())
	}

	err = cfg.AddUser(entry)
	if err != nil {
		return err
	}

	var out strings.Builder
	out.Grow(256)
	fmt.Fprintf(&out, "Added user %q to %q. Restart outboxd for this change to take effect.\n", escapeControl(entry.Username), cfg.Path())

	if generated {
		fmt.Fprintf(&out, "\nGenerated password (store it now; shown once):\n\n  %s\n", password)
	}

	_, err = os.Stdout.WriteString(out.String())
	return err
}

// password reads a password from stdin when it is piped, so unattended setup
// never has to put a plaintext password in argv where ps can read it.
func password() (string, bool, error) {
	info, err := os.Stdin.Stat()
	if err != nil {
		return "", false, err
	}

	if info.Mode()&os.ModeCharDevice != 0 {
		// 26 base32 characters, ~120 bits after lowercasing.
		return strings.ToLower(rand.Text()), true, nil
	}

	// maxPasswordBytes is the maximum accepted piped password length.
	const maxPasswordBytes = 1024
	supplied, err := readPassword(os.Stdin, maxPasswordBytes)
	if err != nil {
		return "", false, err
	}

	return supplied, false, nil
}

// readPassword reads a password from r.
//
// The limit applies to the password after removal of one optional line ending.
// Accepts exactly maxBytes password bytes, optionally followed by a single LF
// or CRLF. Rejects empty input, additional lines, NUL bytes, and passwords
// longer than maxBytes. At most one trailing LF or CRLF is removed; a password
// whose final intended character is '\r' is not over-trimmed.
func readPassword(r io.Reader, maxBytes int) (string, error) {
	if maxBytes <= 0 {
		return "", errors.New("invalid password length limit")
	}

	// maxBytes password + optional CRLF + one overflow detector byte.
	body, err := io.ReadAll(io.LimitReader(r, int64(maxBytes)+3))
	if err != nil {
		return "", err
	}

	pass := body

	switch {
	case len(pass) >= 2 && pass[len(pass)-2] == '\r' && pass[len(pass)-1] == '\n':
		pass = pass[:len(pass)-2]
	case len(pass) >= 1 && pass[len(pass)-1] == '\n':
		pass = pass[:len(pass)-1]
	}

	if len(pass) == 0 {
		return "", errors.New("empty password on stdin")
	}

	if len(pass) > maxBytes {
		return "", fmt.Errorf("password exceeds maximum length of %d bytes", maxBytes)
	}

	// Additional lines after the optional ending, or an embedded newline mid-password.
	if containsByte(pass, '\n') {
		return "", errors.New("password must be a single line")
	}

	// NUL is rejected; treat passwords as opaque UTF-8/binary otherwise.
	if containsByte(pass, 0) {
		return "", errors.New("password contains NUL")
	}

	return string(pass), nil
}

func containsByte(b []byte, c byte) bool {
	return slices.Contains(b, c)
}
