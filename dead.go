package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"text/tabwriter"

	"github.com/coalaura/outboxd/internal/config"
	"github.com/coalaura/outboxd/internal/disk"
	"github.com/coalaura/outboxd/internal/queue"
)

func dead(configPath string, arguments []string) error {
	if len(arguments) == 0 {
		return errors.New("usage: outboxd dead list | show|retry|export|delete <id>")
	}

	cfg, err := config.LoadFile(config.ResolveConfigPath(configPath))
	if err != nil {
		return err
	}

	queueDir := cfg.ResolvePath("queue")

	switch arguments[0] {
	case "list":
		if len(arguments) != 1 {
			return errors.New("usage: outboxd dead list")
		}
		spool, err := queue.OpenReadOnly(queueDir)
		if err != nil {
			return err
		}
		return deadList(spool)
	case "show":
		if len(arguments) != 2 {
			return errors.New("usage: outboxd dead show <id>")
		}
		spool, err := queue.OpenReadOnly(queueDir)
		if err != nil {
			return err
		}
		return deadShow(spool, arguments[1])
	case "export":
		if len(arguments) != 2 {
			return errors.New("usage: outboxd dead export <id>")
		}
		spool, err := queue.OpenReadOnly(queueDir)
		if err != nil {
			return err
		}
		return spool.ExportDead(arguments[1], os.Stdout)
	case "retry":
		if len(arguments) != 2 {
			return errors.New("usage: outboxd dead retry <id>")
		}
		spool, err := queue.Open(queueDir, queue.Limits{
			MaxMessages:         cfg.Server.MaxQueueMessages,
			MaxBytes:            cfg.Server.MaxQueueBytes,
			MaxSpoolBytes:       cfg.Server.MaxSpoolBytes,
			SpoolEmergencyBytes: cfg.Server.SpoolEmergencyBytes,
			MinFreeDisk:         cfg.Server.MinFreeDiskBytes,
			DeadRetention:       config.Duration(cfg.Server.DeadRetention),
			CorruptRetention:    config.Duration(cfg.Server.CorruptRetention),
		})
		if err != nil {
			if errors.Is(err, disk.ErrLocked) {
				return errors.New("outboxd is running and holds the queue lock; stop it before retrying dead-letter messages")
			}
			return err
		}
		defer spool.Close()
		spool.FreeDisk = disk.FreeBytes
		return deadRetry(spool, arguments[1])
	case "delete":
		if len(arguments) != 2 {
			return errors.New("usage: outboxd dead delete <id>")
		}
		spool, err := openAdministrativeSpool(queueDir, cfg)
		if err != nil {
			return err
		}
		defer spool.Close()
		return spool.DeleteDead(arguments[1])
	default:
		return fmt.Errorf("unknown dead subcommand %q", arguments[0])
	}
}

func corrupt(configPath string, arguments []string) error {
	if len(arguments) == 0 {
		return errors.New("usage: outboxd corrupt list | delete <name>")
	}
	cfg, err := config.LoadFile(config.ResolveConfigPath(configPath))
	if err != nil {
		return err
	}
	queueDir := cfg.ResolvePath("queue")
	switch arguments[0] {
	case "list":
		if len(arguments) != 1 {
			return errors.New("usage: outboxd corrupt list")
		}
		spool, err := queue.OpenReadOnly(queueDir)
		if err != nil {
			return err
		}
		ids, err := spool.CorruptIDs()
		if err != nil {
			return err
		}
		for _, id := range ids {
			fmt.Println(id)
		}
		return nil
	case "delete":
		if len(arguments) != 2 {
			return errors.New("usage: outboxd corrupt delete <name>")
		}
		spool, err := openAdministrativeSpool(queueDir, cfg)
		if err != nil {
			return err
		}
		defer spool.Close()
		return spool.DeleteCorrupt(arguments[1])
	default:
		return fmt.Errorf("unknown corrupt subcommand %q", arguments[0])
	}
}

func openAdministrativeSpool(queueDir string, cfg *config.Config) (*queue.Queue, error) {
	spool, err := queue.Open(queueDir, queue.Limits{
		MaxMessages:         cfg.Server.MaxQueueMessages,
		MaxBytes:            cfg.Server.MaxQueueBytes,
		MaxSpoolBytes:       cfg.Server.MaxSpoolBytes,
		SpoolEmergencyBytes: cfg.Server.SpoolEmergencyBytes,
		MinFreeDisk:         cfg.Server.MinFreeDiskBytes,
		DeadRetention:       config.Duration(cfg.Server.DeadRetention),
		CorruptRetention:    config.Duration(cfg.Server.CorruptRetention),
	})
	if errors.Is(err, disk.ErrLocked) {
		return nil, errors.New("outboxd is running and holds the queue lock; stop it before modifying stored queue entries")
	}
	return spool, err
}

func deadList(spool *queue.Queue) error {
	ids, err := spool.DeadIDs()
	if err != nil {
		return err
	}
	if len(ids) == 0 {
		fmt.Println("(no dead-letter messages)")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tSENDER\tRECIPIENTS\tERROR")
	for _, id := range ids {
		env, err := spool.LoadDead(id)
		if err != nil {
			fmt.Fprintf(w, "%s\t?\t?\t%v\n", id, err)
			continue
		}
		fmt.Fprintf(w, "%s\t%s\t%d\t%s\n", env.ID, env.Sender, len(env.Recipients), env.LastError)
	}
	return w.Flush()
}

func deadShow(spool *queue.Queue, id string) error {
	env, err := spool.LoadDead(id)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(env)
}

func deadRetry(spool *queue.Queue, id string) error {
	reportQueueIssues(os.Stderr, spool)
	env, err := spool.ReviveDead(id)
	if err != nil {
		if env != nil {
			return fmt.Errorf("requeued %s, but durability could not be confirmed: %w", env.ID, err)
		}
		return err
	}
	fmt.Printf("requeued %s\n", env.ID)
	return nil
}

func reportQueueIssues(w io.Writer, spool *queue.Queue) {
	for _, err := range spool.Corrupt {
		fmt.Fprintf(w, "corrupt queue entry: %s\n", escapeControl(err.Error()))
	}
	for _, err := range spool.Warnings {
		fmt.Fprintf(w, "queue maintenance warning: %s\n", escapeControl(err.Error()))
	}
}
