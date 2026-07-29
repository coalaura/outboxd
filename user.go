package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/coalaura/outboxd/internal/config"
	"github.com/coalaura/outboxd/internal/passwd"
	"github.com/goccy/go-yaml"
)

func user(arguments []string) error {
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

	err = entry.Validate()
	if err != nil {
		return err
	}

	block, err := yaml.MarshalWithOptions([]config.User{entry}, yaml.Indent(2))
	if err != nil {
		return err
	}

	var out strings.Builder

	out.Grow(len(block) + 512)

	if generated {
		fmt.Fprintf(&out, "\nGenerated password for %s\n\n  %s\n\n", entry.Username, password)
		out.WriteString("Store it now. It is shown once and never written to disk in plaintext.\n")
	}

	out.WriteString("\nAdd the following to the config:\n\nusers:\n")

	for line := range strings.SplitSeq(strings.TrimRight(string(block), "\n"), "\n") {
		fmt.Fprintf(&out, "  %s\n", line)
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

	body, err := io.ReadAll(io.LimitReader(os.Stdin, 1<<10))
	if err != nil {
		return "", false, err
	}

	supplied := strings.Trim(string(body), "\r\n")
	if supplied == "" {
		return "", false, errors.New("empty password on stdin")
	}

	return supplied, false, nil
}
