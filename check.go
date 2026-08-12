package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/coalaura/outboxd/internal/certs"
	"github.com/coalaura/outboxd/internal/check"
	"github.com/coalaura/outboxd/internal/config"
	"github.com/coalaura/outboxd/internal/sign"
)

func runCheck(configPath string) error {
	cfg, err := config.LoadFile(config.ResolveConfigPath(configPath))
	if err != nil {
		return err
	}

	err = cfg.IsReady()
	if err != nil {
		return fmt.Errorf("configuration not ready: %w", err)
	}

	err = verifyBindAddresses(cfg)
	if err != nil {
		return err
	}

	opts := check.Options{Config: cfg, Resolver: check.DefaultResolver{}}

	signer, err := sign.Load(cfg)
	if err != nil {
		return fmt.Errorf("load local DKIM key: %w", err)
	}

	opts.DKIM = &check.DKIMKey{Selector: cfg.DKIM.Selector, PublicKey: signer.PublicKey}

	err = certs.Check(cfg)
	if err != nil {
		return fmt.Errorf("check serving TLS certificate: %w", err)
	}

	signalCtx, stop := terminationContext(context.Background())
	defer stop()

	ctx, cancel := context.WithTimeout(signalCtx, 30*time.Second)
	defer cancel()

	results := check.Run(ctx, opts)

	var failed bool

	for _, r := range results {
		fmt.Printf("%s  %-24s  %s\n", r.Level, escapeControl(r.Name), escapeControl(r.Message))

		if r.Level == check.Fail {
			failed = true
		}
	}

	if failed {
		return errors.New("one or more deployment checks failed")
	}

	return nil
}
