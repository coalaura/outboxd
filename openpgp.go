package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/coalaura/outboxd/internal/config"
	pgpsign "github.com/coalaura/outboxd/internal/openpgp"
)

func openPGPCommand(configPath string, args []string) error {
	if len(args) != 3 || args[0] != "create" {
		return errors.New("usage: outboxd openpgp create <username> <sender>")
	}

	created, err := pgpsign.Create(config.ResolveConfigPath(configPath), args[1], args[2])
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "Created encrypted OpenPGP key %s for %q (user %q).\n", created.Fingerprint, created.Sender, args[1])
	fmt.Fprintf(os.Stdout, "Private key: %s\nPassphrase file: %s\nRestart outboxd for this change to take effect.\n", created.SigningKey, created.PassphraseFile)

	return nil
}
