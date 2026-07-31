package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/coalaura/outboxd/internal/config"
	"github.com/coalaura/outboxd/internal/disk"
	"github.com/coalaura/outboxd/internal/queue"
)

func dead(configPath string, arguments []string) error {
	if len(arguments) == 0 {
		return errors.New("usage: outboxd dead list|show|retry|export <id>")
	}

	cfg, err := config.LoadFile(config.ResolveConfigPath(configPath))
	if err != nil {
		return err
	}

	queueDir := cfg.ResolvePath("queue")

	switch arguments[0] {
	case "list":
		spool, err := queue.OpenReadOnly(queueDir)
		if err != nil {
			return err
		}
		return deadList(spool)
	case "show":
		if len(arguments) < 2 {
			return errors.New("usage: outboxd dead show <id>")
		}
		spool, err := queue.OpenReadOnly(queueDir)
		if err != nil {
			return err
		}
		return deadShow(spool, arguments[1])
	case "export":
		if len(arguments) < 2 {
			return errors.New("usage: outboxd dead export <id>")
		}
		spool, err := queue.OpenReadOnly(queueDir)
		if err != nil {
			return err
		}
		return spool.ExportDead(arguments[1], os.Stdout)
	case "retry":
		if len(arguments) < 2 {
			return errors.New("usage: outboxd dead retry <id>")
		}
		spool, err := queue.Open(queueDir, queue.Limits{
			MaxMessages: cfg.Server.MaxQueueMessages,
			MaxBytes:    cfg.Server.MaxQueueBytes,
			MinFreeDisk: cfg.Server.MinFreeDiskBytes,
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
	default:
		return fmt.Errorf("unknown dead subcommand %q", arguments[0])
	}
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
	env, err := spool.ReviveDead(id)
	if err != nil {
		return err
	}
	fmt.Printf("requeued %s\n", env.ID)
	return nil
}
