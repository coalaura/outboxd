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

	spool, err := queue.Open(cfg.ResolvePath("queue"), queue.Limits{
		MaxMessages: cfg.Server.MaxQueueMessages,
		MaxBytes:    cfg.Server.MaxQueueBytes,
		MinFreeDisk: cfg.Server.MinFreeDiskBytes,
	})
	if err != nil {
		return err
	}
	spool.FreeDisk = disk.FreeBytes

	switch arguments[0] {
	case "list":
		return deadList(spool)
	case "show":
		if len(arguments) < 2 {
			return errors.New("usage: outboxd dead show <id>")
		}
		return deadShow(spool, arguments[1])
	case "retry":
		if len(arguments) < 2 {
			return errors.New("usage: outboxd dead retry <id>")
		}
		return deadRetry(spool, arguments[1])
	case "export":
		if len(arguments) < 2 {
			return errors.New("usage: outboxd dead export <id>")
		}
		return spool.ExportDead(arguments[1], os.Stdout)
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
