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

	cfg, created, err := loadConfig(configPath)
	if err != nil {
		return err
	}
	if created {
		fmt.Fprintf(os.Stderr, "created default config at %s\n", cfg.Path())
	}

	if err := cfg.AddUser(entry); err != nil {
		return err
	}

	var out strings.Builder
	out.Grow(256)
	fmt.Fprintf(&out, "Added user %s to %s\n", entry.Username, cfg.Path())
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
