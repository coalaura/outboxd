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

	_, body, err := records.Write(cfg, signer.Record())
	if err != nil {
		return err
	}

	_, err = os.Stdout.Write(body)

	return err
}
