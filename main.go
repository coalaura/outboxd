package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
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
	"github.com/coalaura/outboxd/internal/sign"
	"github.com/coalaura/outboxd/internal/smtpd"
	"github.com/coalaura/plain"
)

var log = plain.New(plain.WithDate(plain.RFC3339Local))

func main() {
	configPath, args := parseGlobalFlags(os.Args[1:])

	if len(args) == 0 {
		log.MustExit(serve(configPath))
		return
	}

	switch args[0] {
	case "user":
		log.MustExit(user(configPath, args[1:]))
	case "dns":
		if len(args) != 1 {
			log.MustExit(errors.New("usage: outboxd dns"))
			return
		}

		log.MustExit(dns(configPath))
	case "provision":
		if len(args) != 1 {
			log.MustExit(errors.New("usage: outboxd provision"))
			return
		}

		log.MustExit(provision(configPath))
	case "check":
		if len(args) != 1 {
			log.MustExit(errors.New("usage: outboxd check"))
			return
		}

		log.MustExit(runCheck(configPath))
	case "dead":
		log.MustExit(dead(configPath, args[1:]))
	case "corrupt":
		log.MustExit(corrupt(configPath, args[1:]))
	case "serve":
		if len(args) != 1 {
			log.MustExit(errors.New("usage: outboxd serve"))
			return
		}

		log.MustExit(serve(configPath))
	default:
		log.MustExit(fmt.Errorf("unknown command %q, expected user, provision, dns, check, dead, corrupt, or serve (default)", args[0]))
	}
}

// parseGlobalFlags extracts -config / --config before the subcommand.
func parseGlobalFlags(args []string) (configPath string, rest []string) {
	fs := flag.NewFlagSet("outboxd", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.StringVar(&configPath, "config", "", "path to config.yml (or set OUTBOXD_CONFIG)")

	// Stop at first non-flag so subcommands keep their own args.
	err := fs.Parse(args)
	if err != nil {
		// flag package already printed; exit like a normal CLI.
		os.Exit(2)
	}

	return configPath, fs.Args()
}

func ensureConfig(configPath string) (*config.Config, bool, error) {
	return config.EnsurePath(config.ResolveConfigPath(configPath))
}

func loadOperationalConfig(configPath string) (*config.Config, *disk.FileLock, error) {
	path, err := filepath.Abs(config.ResolveConfigPath(configPath))
	if err != nil {
		return nil, nil, err
	}

	// Confirm the configuration exists before creating its synchronization file.
	// Reload after acquiring the lock so the caller receives one owned snapshot.
	_, err = config.LoadFile(path)
	if err != nil {
		return nil, nil, err
	}

	lockPath := path + ".outboxd.lock"
	info, err := os.Lstat(lockPath)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, nil, err
		}
	} else if !info.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("configuration ownership lock is not a regular file: %s", lockPath)
	}

	ownership, err := disk.Lock(lockPath)
	if err != nil {
		return nil, nil, fmt.Errorf("configuration %s: %w: another outboxd operation owns its startup snapshot", path, err)
	}

	cfg, err := config.LoadFile(path)
	if err != nil {
		_ = ownership.Close()
		return nil, nil, err
	}

	return cfg, ownership, nil
}

func lockSpool(cfg *config.Config) (*disk.FileLock, error) {
	queuePath := cfg.ResolvePath("queue")
	info, err := os.Stat(queuePath)
	if err != nil {
		return nil, fmt.Errorf("spool is not provisioned at %s: %w", queuePath, err)
	}

	if !info.IsDir() {
		return nil, fmt.Errorf("spool path is not a directory: %s", queuePath)
	}

	lock, err := disk.Lock(filepath.Join(queuePath, ".lock"))
	if err != nil {
		return nil, fmt.Errorf("spool %s: %w: stop the running daemon before this operation", queuePath, err)
	}

	return lock, nil
}

func provision(configPath string) error {
	cfg, created, err := ensureConfig(configPath)
	if err != nil {
		return err
	}

	if created {
		fmt.Fprintf(os.Stdout, "Created default config at %q. Edit it, then rerun provision. Configuration changes require an outboxd restart.\n", cfg.Path())
		return nil
	}

	ownership, err := disk.Lock(cfg.Path() + ".outboxd.lock")
	if err != nil {
		return fmt.Errorf("configuration %s: %w", cfg.Path(), err)
	}
	defer ownership.Close()

	err = disk.Mkdir(cfg.ResolvedDataDir())
	if err != nil {
		return err
	}

	err = disk.Mkdir(cfg.ResolvePath("queue"))
	if err != nil {
		return err
	}

	spoolOwnership, err := lockSpool(cfg)
	if err != nil {
		return err
	}
	defer spoolOwnership.Close()

	_, generated, err := sign.Ensure(cfg)
	if err != nil {
		return fmt.Errorf("provision DKIM key: %w", err)
	}

	path, err := cfg.ResolveGeneratedPath(cfg.DKIM.PrivateKeyFile)
	if err != nil {
		return err
	}

	if generated {
		fmt.Fprintf(os.Stdout, "Provisioned DKIM key at %q (create-once).\n", path)
	} else {
		fmt.Fprintf(os.Stdout, "DKIM key already provisioned at %q; left unchanged.\n", path)
	}

	return nil
}

func serve(configPath string) error {
	log.Println("Loading config...")

	cfg, ownership, err := loadOperationalConfig(configPath)
	if err != nil {
		return err
	}
	defer ownership.Close()

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
		if closeErr := spool.CloseContext(closeCtx); closeErr != nil {
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

	return errors.Join(errs[0], errs[1])
}

var (
	serviceShutdownTimeout = 45 * time.Second
	queueShutdownTimeout   = 30 * time.Second
)

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

	err = cfg.IsReady()
	if err != nil {
		return fmt.Errorf("configuration not ready: %w", err)
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
