package main

import (
	"bytes"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/coalaura/outboxd/internal/config"
	"github.com/coalaura/outboxd/internal/queue"
)

type administrativeCommandArityCase struct {
	name string
	call func() error
}

func TestReportQueueIssuesEscapesTerminalControls(t *testing.T) {
	spool := &queue.Queue{
		Corrupt:  []error{errors.New("bad\nentry")},
		Warnings: []error{errors.New("warn\tentry")},
	}

	var out bytes.Buffer

	reportQueueIssues(&out, spool)

	got := out.String()

	if strings.Contains(got, "bad\nentry") || strings.Contains(got, "warn\tentry") {
		t.Fatalf("terminal controls were not escaped: %q", got)
	}

	if !strings.Contains(got, `corrupt queue entry: bad\x0aentry`) || !strings.Contains(got, `queue maintenance warning: warn\x09entry`) {
		t.Fatalf("unexpected report: %q", got)
	}
}

func TestAdministrativeCommandsRequireExactArity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yml")

	_, _, err := config.EnsurePath(path)
	if err != nil {
		t.Fatal(err)
	}

	tests := []administrativeCommandArityCase{
		{"queue list extra", func() error {
			return queueCommand(path, []string{"list", "extra"})
		}},
		{"queue show missing", func() error {
			return queueCommand(path, []string{"show"})
		}},
		{"queue show extra", func() error {
			return queueCommand(path, []string{"show", "id", "extra"})
		}},
		{"queue retry extra", func() error {
			return queueCommand(path, []string{"retry", "id", "extra"})
		}},
		{"queue export extra", func() error {
			return queueCommand(path, []string{"export", "id", "extra"})
		}},
		{"queue delete missing", func() error {
			return queueCommand(path, []string{"delete"})
		}},
		{"dead list extra", func() error {
			return dead(path, []string{"list", "extra"})
		}},
		{"dead show missing", func() error {
			return dead(path, []string{"show"})
		}},
		{"dead show extra", func() error {
			return dead(path, []string{"show", "id", "extra"})
		}},
		{"dead retry extra", func() error {
			return dead(path, []string{"retry", "id", "extra"})
		}},
		{"dead export extra", func() error {
			return dead(path, []string{"export", "id", "extra"})
		}},
		{"dead delete missing", func() error {
			return dead(path, []string{"delete"})
		}},
		{"corrupt list extra", func() error {
			return corrupt(path, []string{"list", "extra"})
		}},
		{"corrupt delete missing", func() error {
			return corrupt(path, []string{"delete"})
		}},
		{"corrupt delete extra", func() error {
			return corrupt(path, []string{"delete", "name", "extra"})
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.call()
			if err == nil || !strings.Contains(err.Error(), "usage:") {
				t.Fatalf("error=%v want usage error", err)
			}
		})
	}
}
