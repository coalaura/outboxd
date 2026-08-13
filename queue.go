package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/coalaura/outboxd/internal/config"
	"github.com/coalaura/outboxd/internal/queue"
)

func queueCommand(configPath string, arguments []string) error {
	if len(arguments) == 0 {
		return errors.New("usage: outboxd queue list | show|retry|export|delete <id>")
	}

	cfg, err := config.LoadFile(config.ResolveConfigPath(configPath))
	if err != nil {
		return err
	}

	queueDir := cfg.ResolvePath("queue")

	switch arguments[0] {
	case "list":
		if len(arguments) != 1 {
			return errors.New("usage: outboxd queue list")
		}

		spool, err := queue.OpenReadOnly(queueDir)
		if err != nil {
			return err
		}

		return readyList(spool)
	case "show":
		if len(arguments) != 2 {
			return errors.New("usage: outboxd queue show <id>")
		}

		spool, err := queue.OpenReadOnly(queueDir)
		if err != nil {
			return err
		}

		return readyShow(spool, arguments[1])
	case "export":
		if len(arguments) != 2 {
			return errors.New("usage: outboxd queue export <id>")
		}

		spool, err := queue.OpenReadOnly(queueDir)
		if err != nil {
			return err
		}

		return spool.ExportReady(arguments[1], os.Stdout)
	case "retry":
		if len(arguments) != 2 {
			return errors.New("usage: outboxd queue retry <id>")
		}

		spool, err := openAdministrativeSpool(queueDir, cfg)
		if err != nil {
			return err
		}

		defer spool.Close()

		reportQueueIssues(os.Stderr, spool)

		envelope, err := spool.RetryReady(arguments[1])
		if err != nil {
			return err
		}

		fmt.Printf("queued %s for immediate retry\n", envelope.ID)

		return nil
	case "delete":
		if len(arguments) != 2 {
			return errors.New("usage: outboxd queue delete <id>")
		}

		spool, err := openAdministrativeSpool(queueDir, cfg)
		if err != nil {
			return err
		}

		defer spool.Close()

		return spool.DeleteReady(arguments[1])
	default:
		return fmt.Errorf("unknown queue subcommand %q", arguments[0])
	}
}

func readyList(spool *queue.Queue) error {
	ids, err := spool.ReadyIDs()
	if err != nil {
		return err
	}

	if len(ids) == 0 {
		fmt.Println("(queue is empty)")

		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)

	fmt.Fprintln(w, "ID\tSENDER\tPENDING\tATTEMPTS\tNEXT ATTEMPT\tERROR")

	for _, id := range ids {
		envelope, err := spool.LoadReady(id)
		if err != nil {
			fmt.Fprintf(w, "%s\t?\t?\t?\t?\t%s\n", id, escapeControl(err.Error()))

			continue
		}

		fmt.Fprintf(w, "%s\t%s\t%d\t%d\t%s\t%s\n", envelope.ID, envelope.Sender, envelope.Pending(), envelope.Attempts, envelope.NextAttempt.Format("2006-01-02T15:04:05Z07:00"), escapeControl(envelope.LastError))
	}

	return w.Flush()
}

func readyShow(spool *queue.Queue, id string) error {
	envelope, err := spool.LoadReady(id)
	if err != nil {
		return err
	}

	encoder := json.NewEncoder(os.Stdout)

	encoder.SetIndent("", "  ")

	return encoder.Encode(envelope)
}
