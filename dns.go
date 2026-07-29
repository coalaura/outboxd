package main

import (
	"os"

	"github.com/coalaura/outboxd/internal/config"
	"github.com/coalaura/outboxd/internal/records"
	"github.com/coalaura/outboxd/internal/sign"
)

func dns() error {
	cfg, _, err := config.Ensure()
	if err != nil {
		return err
	}

	signer, _, err := sign.Ensure(cfg)
	if err != nil {
		return err
	}

	path, err := records.Write(cfg, signer.Record())
	if err != nil {
		return err
	}

	body, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	os.Stdout.Write(body)

	return nil
}
