package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/coalaura/outboxd/internal/config"
	pgpsign "github.com/coalaura/outboxd/internal/openpgp"
)

func openPGPCommand(configPath string, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: outboxd openpgp <create|publish> ...")
	}

	switch args[0] {
	case "create":
		if len(args) != 3 {
			return errors.New("usage: outboxd openpgp create <username> <sender>")
		}

		created, err := pgpsign.Create(config.ResolveConfigPath(configPath), args[1], args[2])
		if err != nil {
			return err
		}

		fmt.Fprintf(os.Stdout, "Created encrypted OpenPGP key %s for %q (user %q).\n", created.Fingerprint, created.Sender, args[1])
		fmt.Fprintf(os.Stdout, "Private key: %s\nPassphrase file: %s\nRestart outboxd for this change to take effect.\n", created.SigningKey, created.PassphraseFile)

		return nil
	case "publish":
		if len(args) != 2 {
			return errors.New("usage: outboxd openpgp publish <output-directory>")
		}

		published, err := pgpsign.Publish(config.ResolveConfigPath(configPath), args[1])
		if err != nil {
			return err
		}

		fmt.Fprintf(os.Stdout, "Published %d OpenPGP identity artifacts to %s.\n", len(published), args[1])

		for _, identity := range published {
			fmt.Fprintf(os.Stdout, "%s  %s\n", identity.Fingerprint, identity.Sender)
		}

		return nil
	}

	return errors.New("usage: outboxd openpgp <create|publish> ...")
}
