package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"

	"github.com/coalaura/outboxd/internal/certs"
	"github.com/coalaura/outboxd/internal/check"
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
	configPath, args := parseGlobalFlags(os.Args[1:])

	if len(args) == 0 {
		log.MustFail(serve(configPath))
		return
	}

	switch args[0] {
	case "user":
		log.MustFail(user(configPath, args[1:]))
	case "dns":
		log.MustFail(dns(configPath))
	case "check":
		log.MustFail(runCheck(configPath))
	case "dead":
		log.MustFail(dead(configPath, args[1:]))
	case "serve":
		log.MustFail(serve(configPath))
	default:
		log.MustFail(fmt.Errorf("unknown command %q, expected user, dns, check, dead, or serve (default)", args[0]))
	}
}

// parseGlobalFlags extracts -config / --config before the subcommand.
func parseGlobalFlags(args []string) (configPath string, rest []string) {
	fs := flag.NewFlagSet("outboxd", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.StringVar(&configPath, "config", "", "path to config.yml (or set OUTBOXD_CONFIG)")
	// Stop at first non-flag so subcommands keep their own args.
	if err := fs.Parse(args); err != nil {
		// flag package already printed; exit like a normal CLI.
		os.Exit(2)
	}
	return configPath, fs.Args()
}

func loadConfig(configPath string) (*config.Config, bool, error) {
	return config.EnsurePath(config.ResolveConfigPath(configPath))
}

func serve(configPath string) error {
	log.Println("Loading config...")

	cfg, created, err := loadConfig(configPath)
	if err != nil {
		return err
	}

	if created {
		log.Println("Created default config")
	}

	log.Println("Ensuring data directory...")

	err = disk.Mkdir(cfg.ResolvedDataDir())
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

	if err := verifyBindAddresses(cfg); err != nil {
		return err
	}

	// Exclusive spool lock is daemon ownership: hold it before writing keys/certs.
	spool, err := queue.Open(cfg.ResolvePath("queue"), queue.Limits{
		MaxMessages: cfg.Server.MaxQueueMessages,
		MaxBytes:    cfg.Server.MaxQueueBytes,
		MinFreeDisk: cfg.Server.MinFreeDiskBytes,
	})
	if err != nil {
		return err
	}
	defer spool.Close()
	spool.FreeDisk = disk.FreeBytes

	for _, cerr := range spool.Corrupt {
		log.Warnln("corrupt queue entry:", escapeControl(cerr.Error()))
	}
	for _, warning := range spool.Warnings {
		log.Warnln("queue maintenance warning:", escapeControl(warning.Error()))
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
	keeper.SetReloadErrorHandler(func(err error) {
		log.Warnln("TLS certificate reload failed:", escapeControl(err.Error()))
	})

	log.Println("Writing DNS instructions...")

	path, _, err := records.Write(cfg, signer.Record())
	if err != nil {
		return err
	}

	log.Printf("Wrote DNS instructions to %s\n", strconv.Quote(path))

	log.Println("Starting server...")

	ctx, stop := terminationContext(context.Background())
	defer stop()

	submission := smtpd.New(cfg, keeper, signer, spool, log)

	err = submission.Listen()
	if err != nil {
		return err
	}

	deliverer := deliver.NewWithSigner(cfg, spool, log, signer)

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
		found := false
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

func runCheck(configPath string) error {
	cfg, err := config.LoadFile(config.ResolveConfigPath(configPath))
	if err != nil {
		return err
	}
	if err := cfg.IsReady(); err != nil {
		return fmt.Errorf("configuration not ready: %w", err)
	}

	opts := check.Options{Config: cfg, Resolver: check.DefaultResolver{}}

	signer, err := sign.Load(cfg)
	if err != nil {
		return fmt.Errorf("load local DKIM key: %w", err)
	}
	opts.DKIM = &check.DKIMKey{Selector: cfg.DKIM.Selector, PublicKey: signer.PublicKey}
	if err := certs.Check(cfg); err != nil {
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

// terminationContext stops intercepting signals after the first termination
// request. A second signal therefore regains the operating system's default
// force-termination behavior.
func terminationContext(parent context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(parent)
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	var once sync.Once
	stop := func() {
		once.Do(func() {
			signal.Stop(signals)
			cancel()
		})
	}
	go func() {
		select {
		case <-signals:
			stop()
		case <-parent.Done():
			stop()
		case <-ctx.Done():
		}
	}()
	return ctx, stop
}

func escapeControl(value string) string {
	var out strings.Builder
	for _, r := range value {
		if unicode.IsControl(r) {
			if r <= 0xff {
				fmt.Fprintf(&out, `\x%02x`, r)
			} else {
				fmt.Fprintf(&out, `\u%04x`, r)
			}
			continue
		}
		out.WriteRune(r)
	}
	return out.String()
}
