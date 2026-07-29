package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/coalaura/outboxd/internal/certs"
	"github.com/coalaura/outboxd/internal/config"
	"github.com/coalaura/outboxd/internal/deliver"
	"github.com/coalaura/outboxd/internal/disk"
	"github.com/coalaura/outboxd/internal/queue"
	"github.com/coalaura/outboxd/internal/records"
	"github.com/coalaura/outboxd/internal/sign"
	"github.com/coalaura/outboxd/internal/smtpd"
	"github.com/coalaura/plain"
)

var log = plain.New(plain.WithDate(plain.RFC3339Local))

func main() {
	arguments := os.Args[1:]

	if len(arguments) == 0 {
		log.MustFail(serve())

		return
	}

	switch arguments[0] {
	case "user":
		log.MustFail(user(arguments[1:]))
	case "dns":
		log.MustFail(dns())
	default:
		log.MustFail(fmt.Errorf("unknown command %q, expected user or dns", arguments[0]))
	}
}

func serve() error {
	log.Println("Loading config...")

	cfg, created, err := config.Ensure()
	if err != nil {
		return err
	}

	if created {
		log.Println("Created default config")
	}

	log.Println("Ensuring data directory...")

	err = disk.Mkdir(cfg.Server.DataDirectory)
	if err != nil {
		return err
	}

	for _, warning := range cfg.Warnings() {
		log.Warnln(warning)
	}

	err = cfg.IsReady()
	if err != nil {
		return err
	}

	log.Println("Ensuring DKIM keys...")

	signer, generated, err := sign.Ensure(cfg)
	if err != nil {
		return err
	}

	if generated {
		log.Println("Generated DKIM key")
	}

	log.Println("Ensuring TLS certificates...")

	keeper, generated, err := certs.Ensure(cfg)
	if err != nil {
		return err
	}

	if generated {
		log.Println("Generated self-signed TLS certificate")
	}

	log.Println("Writing DNS instructions...")

	path, err := records.Write(cfg, signer.Record())
	if err != nil {
		return err
	}

	log.Printf("Wrote DNS instructions to %s\n", path)

	spool, err := queue.Open(cfg.ResolvePath("queue"))
	if err != nil {
		return err
	}

	log.Println("Starting server...")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	submission := smtpd.New(cfg, keeper, signer, spool, log)
	deliverer := deliver.New(cfg, spool, log)

	var (
		wg   sync.WaitGroup
		errs [2]error
	)

	wg.Go(func() {
		defer stop()

		errs[0] = submission.Run(ctx)
	})

	wg.Go(func() {
		defer stop()

		errs[1] = deliverer.Run(ctx)
	})

	log.Println("Server ready")

	wg.Wait()

	log.Warnln("Stopped")

	return errors.Join(errs[0], errs[1])
}
