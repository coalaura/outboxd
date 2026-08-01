package main

import (
	"fmt"
	"os"

	"github.com/coalaura/outboxd/internal/records"
	"github.com/coalaura/outboxd/internal/sign"
)

func dns(configPath string) error {
	cfg, ownership, err := loadOperationalConfig(configPath)
	if err != nil {
		return err
	}
	defer ownership.Close()

	spoolOwnership, err := lockSpool(cfg)
	if err != nil {
		return err
	}
	defer spoolOwnership.Close()

	signer, err := sign.Load(cfg)
	if err != nil {
		return fmt.Errorf("load DKIM key (run 'outboxd -config %s provision' first): %w", cfg.Path(), err)
	}

	_, body, err := records.Write(cfg, signer.Record())
	if err != nil {
		return err
	}

	_, err = os.Stdout.Write(body)

	return err
}
