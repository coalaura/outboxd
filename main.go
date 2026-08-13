package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"unicode"

	"github.com/coalaura/outboxd/internal/config"
	"github.com/coalaura/outboxd/internal/disk"
	"github.com/coalaura/outboxd/internal/sign"
	"github.com/coalaura/plain"
)

var log = plain.New(plain.WithDate(plain.RFC3339Local))

var Version = "dev"

func main() {
	configPath, showVersion, args := parseGlobalFlags(os.Args[1:])

	handled, err := handleVersion(showVersion, args, os.Stdout)
	if err != nil {
		log.MustExit(err)

		return
	}

	if handled {
		return
	}

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
		log.MustExit(fmt.Errorf("unknown command %q, expected version, user, provision, dns, check, dead, corrupt, or serve (default)", args[0]))
	}
}

func printVersion(w io.Writer) {
	fmt.Fprintln(w, Version)
}

func handleVersion(showVersion bool, args []string, w io.Writer) (bool, error) {
	if showVersion {
		printVersion(w)

		return true, nil
	}

	if len(args) == 0 || args[0] != "version" {
		return false, nil
	}

	if len(args) != 1 {
		return true, errors.New("usage: outboxd version")
	}

	printVersion(w)

	return true, nil
}

// parseGlobalFlags extracts -config / --config before the subcommand.
func parseGlobalFlags(args []string) (configPath string, showVersion bool, rest []string) {
	fs := flag.NewFlagSet("outboxd", flag.ContinueOnError)

	fs.SetOutput(os.Stderr)
	fs.StringVar(&configPath, "config", "", "path to config.yml (or set OUTBOXD_CONFIG)")
	fs.BoolVar(&showVersion, "version", false, "print version and exit")

	// Stop at first non-flag so subcommands keep their own args.
	err := fs.Parse(args)
	if err != nil {
		// flag package already printed; exit like a normal CLI.
		os.Exit(2)
	}

	return configPath, showVersion, fs.Args()
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

	err := disk.ValidatePath(queuePath)
	if err != nil {
		return nil, fmt.Errorf("validate spool namespace %s: %w", queuePath, err)
	}

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

	err = disk.ValidatePath(cfg.ResolvedDataDir())
	if err != nil {
		return fmt.Errorf("validate data namespace %s: %w", cfg.ResolvedDataDir(), err)
	}

	err = disk.EnsurePrivateRoot(cfg.ResolvedDataDir())
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
