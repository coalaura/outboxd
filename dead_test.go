package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/coalaura/outboxd/internal/queue"
)

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
	if !strings.Contains(got, `corrupt queue entry: bad\x0aentry`) ||
		!strings.Contains(got, `queue maintenance warning: warn\x09entry`) {
		t.Fatalf("unexpected report: %q", got)
	}
}
