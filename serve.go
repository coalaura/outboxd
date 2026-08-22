package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/coalaura/outboxd/internal/certs"
	"github.com/coalaura/outboxd/internal/config"
	"github.com/coalaura/outboxd/internal/deliver"
	"github.com/coalaura/outboxd/internal/disk"
	pgpsign "github.com/coalaura/outboxd/internal/openpgp"
	"github.com/coalaura/outboxd/internal/queue"
	"github.com/coalaura/outboxd/internal/rejection"
	"github.com/coalaura/outboxd/internal/sign"
	"github.com/coalaura/outboxd/internal/smtpd"
)

var (
	serviceShutdownTimeout = 45 * time.Second
	queueShutdownTimeout   = 30 * time.Second
)

func serve(configPath string) error {
	log.Println("Loading config...")

	cfg, ownership, err := loadOperationalConfig(configPath)
	if err != nil {
		return err
	}

	defer ownership.Close()

	log.SetLevel(configuredLogLevel(cfg.LogLevel))

	log.Debugf("Debug logging enabled\n")

	for _, warning := range cfg.Warnings() {
		log.Warnln(warning)
	}

	err = cfg.IsReady()
	if err != nil {
		return err
	}

	err = verifyBindAddresses(cfg)
	if err != nil {
		return err
	}

	log.Println("Loading DKIM key...")

	signer, err := sign.Load(cfg)
	if err != nil {
		return fmt.Errorf("load DKIM key (run 'outboxd -config %s provision' first): %w", cfg.Path(), err)
	}

	log.Println("Loading OpenPGP signing keys...")

	pgpSigners, err := pgpsign.Load(cfg)
	if err != nil {
		return fmt.Errorf("load OpenPGP signing keys: %w", err)
	}

	// Exclusive spool lock is daemon ownership: hold it before writing certs.
	spool, err := queue.Open(cfg.ResolvePath("queue"), queue.Limits{
		MaxMessages:         cfg.Server.MaxQueueMessages,
		MaxBytes:            cfg.Server.MaxQueueBytes,
		MaxMessagesPerUser:  cfg.Server.MaxQueueMessagesPerUser,
		MaxBytesPerUser:     cfg.Server.MaxQueueBytesPerUser,
		MaxSpoolBytes:       cfg.Server.MaxSpoolBytes,
		SpoolEmergencyBytes: cfg.Server.SpoolEmergencyBytes,
		MinFreeDisk:         cfg.Server.MinFreeDiskBytes,
		DeadRetention:       config.Duration(cfg.Server.DeadRetention),
		CorruptRetention:    config.Duration(cfg.Server.CorruptRetention),
	})

	if err != nil {
		return err
	}

	defer func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), queueShutdownTimeout)
		defer cancel()

		closeErr := spool.CloseContext(closeCtx)
		if closeErr != nil {
			log.Warnln("queue shutdown incomplete:", escapeControl(closeErr.Error()))
		}
	}()

	spool.FreeDisk = disk.FreeBytes

	for _, cerr := range spool.Corrupt {
		log.Warnln("corrupt queue entry:", escapeControl(cerr.Error()))
	}

	for _, warning := range spool.Warnings {
		log.Warnln("queue maintenance warning:", escapeControl(warning.Error()))
	}

	logSpoolStats(spool)

	log.Println("Ensuring TLS certificates...")

	keeper, generated, err := certs.Ensure(cfg)
	if err != nil {
		return err
	}

	if generated {
		log.Println("Generated self-signed TLS certificate")
	}

	keeper.SetReloadErrorHandler(func(err error) {
		log.Warnln("TLS certificate reload failed:", escapeControl(err.Error()))
	})

	log.Println("Starting server...")

	ctx, stop := terminationContext(context.Background())
	defer stop()

	submission := smtpd.NewWithOpenPGP(cfg, keeper, signer, pgpSigners, spool, log)

	err = submission.Listen()
	if err != nil {
		return err
	}

	var replyRejection *rejection.Server

	if cfg.ReplyRejection.Enabled {
		replyRejection = rejection.New(cfg, log)

		err = replyRejection.Listen()
		if err != nil {
			submission.CloseListeners()

			return err
		}
	}

	deliverer := deliver.NewWithSigner(cfg, spool, log, signer)

	var (
		wg   sync.WaitGroup
		errs [3]error
	)

	wg.Go(func() {
		defer stop()

		errs[0] = submission.Run(ctx)
	})

	wg.Go(func() {
		defer stop()

		errs[1] = deliverer.Run(ctx)
	})

	if replyRejection != nil {
		wg.Go(func() {
			defer stop()

			errs[2] = replyRejection.Run(ctx)
		})
	}

	wg.Go(func() {
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				dead, corrupt, err := spool.Prune(now)
				if err != nil {
					log.Warnln("queue prune failed:", escapeControl(err.Error()))
				} else if dead+corrupt > 0 {
					log.Printf("Pruned %d dead and %d corrupt queue entries\n", dead, corrupt)
				}

				logSpoolStats(spool)
			}
		}
	})

	log.Println("Server ready")

	done := make(chan struct{})

	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-ctx.Done():
		timer := time.NewTimer(serviceShutdownTimeout)
		defer timer.Stop()

		select {
		case <-done:
		case <-timer.C:
			return errors.New("service shutdown exceeded its deadline")
		}
	}

	log.Warnln("Stopped")

	return errors.Join(errs[:]...)
}

func logSpoolStats(spool *queue.Queue) {
	stats := spool.SpoolStats()
	message := fmt.Sprintf("Spool estimated usage: %d bytes used, %d reserved, %d admission limit", stats.Used, stats.Reserved, stats.Limit)

	if stats.HighWater {
		log.Warnln("HIGH WATER:", message)

		return
	}

	log.Println(message)
}

// verifyBindAddresses ensures configured outbound bind IPs exist on this host.
func verifyBindAddresses(cfg *config.Config) error {
	need := make([]net.IP, 0, 2)

	if cfg.Delivery.BindIPv4 != "" {
		ip := net.ParseIP(cfg.Delivery.BindIPv4)
		if ip == nil || ip.To4() == nil {
			return fmt.Errorf("invalid delivery.bind_ipv4 %q", cfg.Delivery.BindIPv4)
		}

		need = append(need, ip)
	}

	if cfg.Delivery.BindIPv6 != "" {
		ip := net.ParseIP(cfg.Delivery.BindIPv6)
		if ip == nil || ip.To4() != nil {
			return fmt.Errorf("invalid delivery.bind_ipv6 %q", cfg.Delivery.BindIPv6)
		}

		need = append(need, ip)
	}

	if len(need) == 0 {
		return nil
	}

	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return fmt.Errorf("list interface addresses: %w", err)
	}

	local := make([]net.IP, 0, len(addrs))

	for _, a := range addrs {
		var ip net.IP

		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}

		if ip != nil {
			local = append(local, ip)
		}
	}

	for _, want := range need {
		var found bool

		for _, have := range local {
			if have.Equal(want) {
				found = true

				break
			}
		}

		if !found {
			return fmt.Errorf("delivery bind address %s is not configured on any local interface", want)
		}
	}

	return nil
}
