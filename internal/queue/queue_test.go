package queue

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coalaura/outboxd/internal/disk"
)

type addFaultCase struct {
	name  string
	hooks func(id string) disk.Hooks
}

type uncommittedTmpAddStateCase struct {
	name string
	body []byte
}

type uncommittedReadyAddStateCase struct {
	name string
	body []byte
}

type recipientSMTPStatusCase struct {
	status Status
	code   int
}

type bodySizeMismatchCase struct {
	name     string
	metadata int64
	body     []byte
}

type envelopeBoundsCase struct {
	name string
	env  *Envelope
}

type queueEntrySizeCase struct {
	id   string
	name string
	size int
}

func clearHooks(t *testing.T) {
	t.Helper()
	t.Cleanup(func() { disk.SetHooks(disk.Hooks{}) })
	disk.SetHooks(disk.Hooks{})
}

func testEnv(id string) *Envelope {
	now := time.Now().UTC().Truncate(time.Second)
	return &Envelope{
		ID:          id,
		Incarnation: strings.Repeat("0", 32),
		Revision:    1,
		Username:    "alice",
		Sender:      "alice@example.com",
		Recipients: []Recipient{
			{Address: "bob@example.com", Domain: "example.com", Status: StatusPending},
		},
		Created:     now,
		NextAttempt: now,
	}
}

func testDSN(source *Envelope) *Envelope {
	env := testEnv(DSNID(source.ID, source.Incarnation, source.DSNGeneration))
	env.Sender = ""
	env.DSNSourceID = source.ID
	env.DSNSourceIncarnation = source.Incarnation
	env.DSNGeneration = source.DSNGeneration
	return env
}

func mustOpen(t *testing.T, dir string, limits Limits) *Queue {
	t.Helper()
	q, err := Open(dir, limits)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	t.Cleanup(func() { _ = q.Close() })
	return q
}

// mustReopen closes prev then opens dir again (exclusive lock).
func mustReopen(t *testing.T, prev *Queue, dir string, limits Limits) *Queue {
	t.Helper()

	if prev != nil {
		err := prev.Close()
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	}

	return mustOpen(t, dir, limits)
}

func corruptEntries(t *testing.T, root string) []string {
	t.Helper()
	corr := filepath.Join(root, dirCorrupt)
	entries, err := os.ReadDir(corr)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}

		t.Fatal(err)
	}

	names := make([]string, 0, len(entries))

	for _, e := range entries {
		names = append(names, e.Name())
	}

	return names
}

func writeAcceptedMarker(t *testing.T, dir string) {
	t.Helper()

	err := os.WriteFile(filepath.Join(dir, addStateName), []byte(addAccepted), 0600)
	if err != nil {
		t.Fatal(err)
	}
}

func writeQueueEntry(t *testing.T, root, namespace string, env *Envelope, body []byte) string {
	t.Helper()
	dir := filepath.Join(root, namespace, env.ID)
	err := os.MkdirAll(dir, 0700)
	if err != nil {
		t.Fatal(err)
	}

	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile(filepath.Join(dir, metaName), raw, 0600)
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile(filepath.Join(dir, bodyName), body, 0600)
	if err != nil {
		t.Fatal(err)
	}

	writeAcceptedMarker(t, dir)
	return dir
}

func TestAddPersistsAndOpenRecovers(t *testing.T) {
	clearHooks(t)
	root := t.TempDir()
	q := mustOpen(t, root, Limits{})

	body := []byte("From: a\r\nTo: b\r\n\r\nhello\r\n")
	env := testEnv("msg001")
	err := q.Add(env, body)
	if err != nil {
		t.Fatal(err)
	}

	metaPath := filepath.Join(root, dirReady, "msg001", metaName)
	bodyPath := filepath.Join(root, dirReady, "msg001", bodyName)
	statePath := filepath.Join(root, dirReady, "msg001", addStateName)
	_, err = os.Stat(metaPath)
	if err != nil {
		t.Fatalf("meta missing: %v", err)
	}

	_, err = os.Stat(bodyPath)
	if err != nil {
		t.Fatalf("body missing: %v", err)
	}

	state, err := os.ReadFile(statePath)
	if err != nil || string(state) != addAccepted {
		t.Fatalf("accepted state missing: %v %q", err, state)
	}

	gotBody, err := os.ReadFile(bodyPath)
	if err != nil || string(gotBody) != string(body) {
		t.Fatalf("body mismatch: %v %q", err, gotBody)
	}

	// Restart: new Open recovers the message.
	q2 := mustReopen(t, q, root, Limits{})
	if q2.Len() != 1 {
		t.Fatalf("Len=%d want 1", q2.Len())
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	got, err := q2.Next(ctx)
	if err != nil {
		t.Fatal(err)
	}

	if got.ID != "msg001" || got.Username != "alice" {
		t.Fatalf("unexpected envelope %#v", got)
	}
}

func TestAddFaultInjectionRecoverable(t *testing.T) {
	clearHooks(t)
	root := t.TempDir()

	cases := []addFaultCase{
		{
			name: "after_body_sync",
			hooks: func(id string) disk.Hooks {
				return disk.Hooks{
					AfterSyncFile: func(path string) error {
						if strings.Contains(path, bodyName) || strings.HasSuffix(filepath.Base(path), bodyName) ||
							strings.Contains(filepath.Base(path), bodyName) {
							return errors.New("inject after body sync")
						}

						// temp files named .message.eml.tmp-*
						if strings.Contains(path, "message.eml") {
							return errors.New("inject after body sync")
						}

						return nil
					},
				}
			},
		},
		{
			name: "after_meta_write",
			hooks: func(id string) disk.Hooks {
				var bodyDone atomic.Bool
				return disk.Hooks{
					AfterSyncFile: func(path string) error {
						if strings.Contains(path, "message.eml") {
							bodyDone.Store(true)
							return nil
						}

						if bodyDone.Load() && strings.Contains(path, "meta.json") {
							return errors.New("inject after meta write")
						}

						return nil
					},
				}
			},
		},
		{
			name: "after_ready_rename",
			hooks: func(id string) disk.Hooks {
				return disk.Hooks{
					AfterRename: func(oldpath, newpath string) error {
						if strings.Contains(newpath, filepath.Join(dirReady, id)) ||
							strings.Contains(newpath, dirReady+string(filepath.Separator)+id) {
							return errors.New("inject after ready rename")
						}

						return nil
					},
				}
			},
		},
		{
			name: "after_ready_sync",
			hooks: func(id string) disk.Hooks {
				return disk.Hooks{
					AfterSyncDir: func(path string) error {
						if filepath.Base(path) == dirReady {
							return errors.New("inject after ready sync")
						}

						return nil
					},
				}
			},
		},
		{
			name: "after_source_sync",
			hooks: func(id string) disk.Hooks {
				return disk.Hooks{
					AfterSyncDir: func(path string) error {
						if filepath.Clean(path) == filepath.Join(root, dirTmp) {
							return errors.New("inject after source sync")
						}

						return nil
					},
				}
			},
		},
		{
			name: "before_acceptance_sync",
			hooks: func(id string) disk.Hooks {
				return disk.Hooks{
					BeforeSyncFile: func(path string) error {
						if filepath.Base(path) == addStateName {
							return errors.New("inject before acceptance sync")
						}

						return nil
					},
				}
			},
		},
		{
			name: "at_acceptance_sync",
			hooks: func(id string) disk.Hooks {
				return disk.Hooks{
					AfterSyncFile: func(path string) error {
						if filepath.Base(path) == addStateName {
							return errors.New("inject at acceptance sync")
						}

						return nil
					},
				}
			},
		},
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id := fmt.Sprintf("fault%d", i)
			q := mustOpen(t, root, Limits{})
			disk.SetHooks(tc.hooks(id))
			t.Cleanup(func() { disk.SetHooks(disk.Hooks{}) })

			err := q.Add(testEnv(id), []byte("body\r\n"))
			if err == nil {
				t.Fatal("expected Add error")
			}

			disk.SetHooks(disk.Hooks{})
			q2 := mustReopen(t, q, root, Limits{})
			readyPath := filepath.Join(root, dirReady, id)
			tmpPath := filepath.Join(root, dirTmp, id)
			if q2.Len() != 0 {
				t.Fatalf("Add returned an error but restart scheduled %d message(s)", q2.Len())
			}

			_, err = os.Stat(readyPath)
			if !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("uncommitted ready entry was not quarantined: %v", err)
			}

			_, err = os.Stat(tmpPath)
			if err == nil {
				t.Fatal("tmp dir left after Open")
			}
		})
	}
}

func TestRecoverTmpNeverPromotesCompleteUncommittedAdd(t *testing.T) {
	clearHooks(t)

	for _, state := range []uncommittedTmpAddStateCase{
		{name: "markerless"},
		{name: "pending", body: []byte(addPending)},
		{name: "accepted", body: []byte(addAccepted)},
	} {

		t.Run(state.name, func(t *testing.T) {
			root := t.TempDir()
			_ = mustOpen(t, root, Limits{}).Close()
			id := "tmp-" + state.name
			dir := filepath.Join(root, dirTmp, id)
			err := os.MkdirAll(dir, 0700)
			if err != nil {
				t.Fatal(err)
			}

			env := testEnv(id)
			message := []byte("complete body\r\n")
			env.Size = int64(len(message))
			meta, err := json.Marshal(env)
			if err != nil {
				t.Fatal(err)
			}

			err = os.WriteFile(filepath.Join(dir, bodyName), message, 0600)
			if err != nil {
				t.Fatal(err)
			}

			err = os.WriteFile(filepath.Join(dir, metaName), meta, 0600)
			if err != nil {
				t.Fatal(err)
			}

			if state.body != nil {
				err = os.WriteFile(filepath.Join(dir, addStateName), state.body, 0600)
				if err != nil {
					t.Fatal(err)
				}
			}

			q := mustOpen(t, root, Limits{})
			if q.Len() != 0 {
				t.Fatalf("uncommitted tmp entry was scheduled, Len=%d", q.Len())
			}

			_, err = os.Stat(filepath.Join(root, dirReady, id))
			if !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("uncommitted tmp entry was promoted: %v", err)
			}

			if len(q.Corrupt) == 0 || len(corruptEntries(t, root)) == 0 {
				t.Fatal("uncommitted tmp entry was not quarantined")
			}
		})
	}
}

func TestOpenRejectsUncommittedReadyAdd(t *testing.T) {
	clearHooks(t)

	for _, state := range []uncommittedReadyAddStateCase{
		{name: "missing"},
		{name: "pending", body: []byte(addPending)},
		{name: "malformed", body: []byte("outboxd-add-v1:accept")},
	} {

		t.Run(state.name, func(t *testing.T) {
			root := t.TempDir()
			_ = mustOpen(t, root, Limits{}).Close()
			id := "ready-" + state.name
			dir := filepath.Join(root, dirReady, id)
			err := os.MkdirAll(dir, 0700)
			if err != nil {
				t.Fatal(err)
			}

			message := []byte("complete body\r\n")
			env := testEnv(id)
			env.Size = int64(len(message))
			meta, err := json.Marshal(env)
			if err != nil {
				t.Fatal(err)
			}

			for name, body := range map[string][]byte{bodyName: message, metaName: meta} {

				err = os.WriteFile(filepath.Join(dir, name), body, 0600)
				if err != nil {
					t.Fatal(err)
				}
			}

			if state.body != nil {
				err = os.WriteFile(filepath.Join(dir, addStateName), state.body, 0600)
				if err != nil {
					t.Fatal(err)
				}
			}

			q := mustOpen(t, root, Limits{})
			if q.Len() != 0 {
				t.Fatalf("uncommitted ready entry was scheduled, Len=%d", q.Len())
			}

			if len(q.Corrupt) == 0 || len(corruptEntries(t, root)) == 0 {
				t.Fatal("uncommitted ready entry was not quarantined")
			}
		})
	}
}

func TestMetaWithoutBodyQuarantine(t *testing.T) {
	clearHooks(t)
	root := t.TempDir()
	_ = mustOpen(t, root, Limits{}).Close() // create layout

	id := "orphanmeta"
	dir := filepath.Join(root, dirReady, id)
	err := os.MkdirAll(dir, 0700)
	if err != nil {
		t.Fatal(err)
	}

	env := testEnv(id)
	raw, _ := json.Marshal(env)
	err = os.WriteFile(filepath.Join(dir, metaName), raw, 0600)
	if err != nil {
		t.Fatal(err)
	}

	writeAcceptedMarker(t, dir)

	q := mustOpen(t, root, Limits{})
	if q.Len() != 0 {
		t.Fatalf("expected not scheduled, Len=%d", q.Len())
	}

	if len(q.Corrupt) == 0 {
		t.Fatal("expected corrupt event")
	}

	n := len(corruptEntries(t, root))
	if n == 0 {
		t.Fatal("expected quarantine dir entries")
	}

	_, err = os.Stat(dir)
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("source should be moved, err=%v", err)
	}
}

func TestBodyWithoutMetaQuarantine(t *testing.T) {
	clearHooks(t)
	root := t.TempDir()
	_ = mustOpen(t, root, Limits{}).Close()

	id := "orphanbody"
	dir := filepath.Join(root, dirReady, id)
	err := os.MkdirAll(dir, 0700)
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile(filepath.Join(dir, bodyName), []byte("x"), 0600)
	if err != nil {
		t.Fatal(err)
	}

	writeAcceptedMarker(t, dir)

	q := mustOpen(t, root, Limits{})
	if q.Len() != 0 {
		t.Fatalf("Len=%d", q.Len())
	}

	if len(q.Corrupt) == 0 {
		t.Fatal("expected corrupt")
	}

	if len(corruptEntries(t, root)) == 0 {
		t.Fatal("expected quarantine")
	}
}

func TestInvalidJSONQuarantine(t *testing.T) {
	clearHooks(t)
	root := t.TempDir()
	_ = mustOpen(t, root, Limits{}).Close()

	id := "badjson"
	dir := filepath.Join(root, dirReady, id)
	err := os.MkdirAll(dir, 0700)
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile(filepath.Join(dir, metaName), []byte("{not json"), 0600)
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile(filepath.Join(dir, bodyName), []byte("x"), 0600)
	if err != nil {
		t.Fatal(err)
	}

	writeAcceptedMarker(t, dir)

	q := mustOpen(t, root, Limits{})
	if q.Len() != 0 {
		t.Fatal("should not schedule")
	}

	if len(q.Corrupt) == 0 || len(corruptEntries(t, root)) == 0 {
		t.Fatal("expected quarantine")
	}
}

func TestIDFilenameMismatchQuarantine(t *testing.T) {
	clearHooks(t)
	root := t.TempDir()
	_ = mustOpen(t, root, Limits{}).Close()

	id := "dirid1"
	dir := filepath.Join(root, dirReady, id)
	err := os.MkdirAll(dir, 0700)
	if err != nil {
		t.Fatal(err)
	}

	env := testEnv("otherid1")
	raw, _ := json.Marshal(env)
	err = os.WriteFile(filepath.Join(dir, metaName), raw, 0600)
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile(filepath.Join(dir, bodyName), []byte("x"), 0600)
	if err != nil {
		t.Fatal(err)
	}

	writeAcceptedMarker(t, dir)

	q := mustOpen(t, root, Limits{})
	if q.Len() != 0 {
		t.Fatal("should not schedule")
	}

	if len(q.Corrupt) == 0 || len(corruptEntries(t, root)) == 0 {
		t.Fatal("expected quarantine")
	}
}

func TestValidateIDAndAddRejectTraversal(t *testing.T) {
	clearHooks(t)
	root := t.TempDir()
	q := mustOpen(t, root, Limits{})

	bad := []string{
		"../etc",
		"..\\windows",
		"a/b",
		"a\\b",
		"",
		".",
		"..",
		"/abs",
		"has space",
		strings.Repeat("a", 200),
	}

	for _, id := range bad {
		err := ValidateID(id)
		if err == nil {
			t.Errorf("ValidateID(%q) want error", id)
		}

		env := testEnv("ok")
		env.ID = id
		err = q.Add(env, []byte("x"))
		if err == nil {
			t.Errorf("Add(%q) want error", id)
		}
	}
}

func TestInvalidRecipientStatusRejected(t *testing.T) {
	clearHooks(t)
	root := t.TempDir()
	q := mustOpen(t, root, Limits{})
	env := testEnv("badstat")
	env.Recipients[0].Status = Status("exploded")
	err := q.Add(env, []byte("x"))
	if err == nil {
		t.Fatal("expected invalid status rejection")
	}
}

func TestInvalidEnhancedRecipientStatusRejected(t *testing.T) {
	clearHooks(t)
	q := mustOpen(t, t.TempDir(), Limits{})
	env := testEnv("invalid-enhanced-status")
	env.Recipients[0].Code = 550
	env.Recipients[0].EnhancedCode = "4.1.1"
	err := q.Add(env, []byte("body"))
	if err == nil {
		t.Fatal("accepted enhanced status whose class conflicts with basic code")
	}
}

func TestEnhancedRecipientStatusRequiresBasicCode(t *testing.T) {
	clearHooks(t)
	q := mustOpen(t, t.TempDir(), Limits{})
	env := testEnv("enhanced-without-basic")
	env.Recipients[0].EnhancedCode = "5.1.1"
	err := q.Add(env, []byte("body"))
	if err == nil {
		t.Fatal("accepted enhanced status without basic SMTP code")
	}
}

func TestRecipientStatusRejectsContradictorySMTPCode(t *testing.T) {
	clearHooks(t)
	q := mustOpen(t, t.TempDir(), Limits{})
	tests := []recipientSMTPStatusCase{
		{"", 550},
		{StatusPending, 451},
		{StatusSent, 550},
		{StatusFailed, 250},
		{StatusFailed, 451},
	}

	for i, tt := range tests {
		env := testEnv(fmt.Sprintf("contradictory-status-%d", i))
		env.Recipients[0].Status = tt.status
		env.Recipients[0].Code = tt.code
		err := q.Add(env, []byte("body"))
		if err == nil {
			t.Fatalf("accepted status=%s code=%d", tt.status, tt.code)
		}
	}
}

func TestRecipientDetailRejectsDisplayControls(t *testing.T) {
	clearHooks(t)
	q := mustOpen(t, t.TempDir(), Limits{})

	for i, detail := range []string{"line\nfeed", "bidi\u202eoverride", "zero\u200bwidth", "separator\u2028line"} {

		env := testEnv(fmt.Sprintf("detail-control-%d", i))
		env.Recipients[0].Status = StatusFailed
		env.Recipients[0].Detail = detail
		err := q.Add(env, []byte("body"))
		if err == nil {
			t.Fatalf("accepted detail %q", detail)
		}
	}
}

func TestRetryPersistenceFailureStillRecoverable(t *testing.T) {
	clearHooks(t)
	root := t.TempDir()
	q := mustOpen(t, root, Limits{})
	env := testEnv("retry1")
	err := q.Add(env, []byte("body\r\n"))
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	got, err := q.Next(ctx)
	if err != nil {
		t.Fatal(err)
	}

	got.Attempts = 1
	got.LastError = "temp fail"
	got.NextAttempt = time.Now().Add(time.Hour)

	disk.SetHooks(disk.Hooks{
		AfterSyncFile: func(path string) error {
			if strings.Contains(path, "meta.json") {
				return errors.New("inject meta write fail")
			}

			return nil
		},
	})
	t.Cleanup(func() { disk.SetHooks(disk.Hooks{}) })

	err = q.Retry(got)
	if err == nil {
		t.Fatal("Retry should fail")
	}

	// Still recoverable via Open (and rescheduled in memory).
	if q.Len() != 1 {
		t.Fatalf("expected rescheduled Len=1 got %d", q.Len())
	}

	disk.SetHooks(disk.Hooks{})
	q2 := mustReopen(t, q, root, Limits{})
	if q2.Len() != 1 {
		t.Fatalf("Open recover Len=%d", q2.Len())
	}
}

func TestRetryReconcilesPostRenameMetadataError(t *testing.T) {
	clearHooks(t)
	root := t.TempDir()
	q := mustOpen(t, root, Limits{})
	env := testEnv("retry-post-rename")
	err := q.Add(env, []byte("body"))
	if err != nil {
		t.Fatal(err)
	}

	got, err := q.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	got.Attempts++
	priorRevision := got.Revision
	wantErr := errors.New("inject post-rename metadata error")
	disk.SetHooks(disk.Hooks{AfterRename: func(oldpath, newpath string) error {
		if filepath.Clean(newpath) == filepath.Join(root, dirReady, got.ID, metaName) {
			return wantErr
		}

		return nil
	}})

	err = q.Retry(got)
	if !errors.Is(err, wantErr) {
		t.Fatalf("Retry error=%v, want %v", err, wantErr)
	}

	disk.SetHooks(disk.Hooks{})

	if got.Revision != priorRevision+1 {
		t.Fatalf("Revision=%d want %d", got.Revision, priorRevision+1)
	}

	retried, err := q.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	err = q.Finish(retried)
	if err != nil {
		t.Fatalf("finish reconciled retry: %v", err)
	}
}

func TestRetryReleasesOwnershipBeforeScheduling(t *testing.T) {
	clearHooks(t)
	q := mustOpen(t, t.TempDir(), Limits{})
	env := testEnv("retry-consumer-handoff")
	err := q.Add(env, []byte("body"))
	if err != nil {
		t.Fatal(err)
	}

	got, err := q.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	published := make(chan struct{})
	release := make(chan struct{})
	q.afterPublish = func() {
		close(published)
		<-release
	}
	result := make(chan error, 1)
	go func() {
		result <- q.Retry(got)
	}()
	<-published
	retried, err := q.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	err = q.Finish(retried)
	if err != nil {
		t.Fatalf("immediate retried-message consumer: %v", err)
	}

	close(release)

	err = <-result
	if err != nil {
		t.Fatal(err)
	}
}

func TestBuryAtomic(t *testing.T) {
	clearHooks(t)
	root := t.TempDir()
	q := mustOpen(t, root, Limits{})
	env := testEnv("bury1")
	err := q.Add(env, []byte("body\r\n"))
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	got, err := q.Next(ctx)
	if err != nil {
		t.Fatal(err)
	}

	got.Recipients[0].Status = StatusFailed
	got.LastError = "perm"

	err = q.Bury(got)
	if err != nil {
		t.Fatal(err)
	}

	_, err = os.Stat(filepath.Join(root, dirDead, "bury1", metaName))
	if err != nil {
		t.Fatal(err)
	}

	_, err = os.Stat(filepath.Join(root, dirReady, "bury1"))
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatal("still in ready")
	}

	// Partial fail: meta ok then rename fails — still recoverable.
	env2 := testEnv("bury2")
	err = q.Add(env2, []byte("body2\r\n"))
	if err != nil {
		t.Fatal(err)
	}

	got2, err := q.Next(ctx)
	if err != nil {
		t.Fatal(err)
	}

	got2.Recipients[0].Status = StatusFailed
	disk.SetHooks(disk.Hooks{
		BeforeRename: func(oldpath, newpath string) error {
			if strings.Contains(newpath, dirDead) {
				return errors.New("inject bury rename fail")
			}

			return nil
		},
	})
	t.Cleanup(func() { disk.SetHooks(disk.Hooks{}) })

	err = q.Bury(got2)
	if err == nil {
		t.Fatal("expected bury error")
	}

	disk.SetHooks(disk.Hooks{})
	q2 := mustReopen(t, q, root, Limits{})
	found := false

	for q2.Len() > 0 {
		e, err := q2.Next(ctx)
		if err != nil {
			break
		}

		if e.ID == "bury2" {
			found = true
		}
	}

	if !found {
		// May still be in ready after failed bury
		_, err = os.Stat(filepath.Join(root, dirReady, "bury2"))
		if err != nil {
			t.Fatal("bury2 not recoverable")
		}
	}
}

func TestBuryDoesNotHideReadyMarkerError(t *testing.T) {
	clearHooks(t)
	root := t.TempDir()
	q := mustOpen(t, root, Limits{})
	env := testEnv("bury-bad-marker")
	err := q.Add(env, []byte("body"))
	if err != nil {
		t.Fatal(err)
	}

	got, err := q.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	got.Recipients[0].Status = StatusFailed
	err = os.WriteFile(filepath.Join(root, dirReady, got.ID, addStateName), []byte("invalid"), 0600)
	if err != nil {
		t.Fatal(err)
	}

	err = os.Mkdir(filepath.Join(root, dirDead, got.ID), 0700)
	if err != nil {
		t.Fatal(err)
	}

	err = q.Bury(got)
	if err == nil {
		t.Fatal("Bury should report the invalid ready marker")
	}

	if q.Len() != 1 {
		t.Fatalf("Len=%d want 1", q.Len())
	}

	messages, bytes := q.Stats()
	if messages != 1 || bytes != 4 {
		t.Fatalf("Stats=(%d, %d) want (1, 4)", messages, bytes)
	}

	_, err = os.Stat(filepath.Join(root, dirReady, got.ID))
	if err != nil {
		t.Fatalf("ready entry removed: %v", err)
	}
}

func TestFinishCrashSafeTrash(t *testing.T) {
	clearHooks(t)
	root := t.TempDir()
	q := mustOpen(t, root, Limits{})
	env := testEnv("fin1")
	err := q.Add(env, []byte("body\r\n"))
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	got, err := q.Next(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Crash after trash rename: leave trash dir entry, ensure Open cleans it and not in ready.
	var trashDst string
	disk.SetHooks(disk.Hooks{
		AfterRename: func(oldpath, newpath string) error {
			if strings.Contains(newpath, dirTrash) {
				trashDst = newpath
				return errors.New("inject after trash rename")
			}

			return nil
		},
	})
	t.Cleanup(func() { disk.SetHooks(disk.Hooks{}) })
	_ = q.Finish(got) // may error after rename
	disk.SetHooks(disk.Hooks{})

	// ready must not hold finish-committed id if rename succeeded
	if trashDst != "" {
		_, err = os.Stat(filepath.Join(root, dirReady, "fin1"))
		if err == nil {
			t.Fatal("still in ready after trash rename")
		}
	}

	q2 := mustReopen(t, q, root, Limits{})
	if q2.Len() != 0 {
		// Only if Finish never renamed
		if trashDst != "" {
			t.Fatalf("Open still scheduled finished msg Len=%d", q2.Len())
		}
	}

	// trash cleaned
	entries, _ := os.ReadDir(filepath.Join(root, dirTrash))
	if len(entries) != 0 {
		t.Fatalf("trash not cleaned: %v", entries)
	}
}

func TestFinishIsIdempotentByID(t *testing.T) {
	clearHooks(t)
	q := mustOpen(t, t.TempDir(), Limits{})
	a := testEnv("finish-a")
	b := testEnv("finish-b")
	a.NextAttempt = time.Now().Add(-time.Minute)
	b.NextAttempt = time.Now().Add(-time.Second)
	err := q.Add(a, []byte("a"))
	if err != nil {
		t.Fatal(err)
	}

	err = q.Add(b, []byte("bbbbb"))
	if err != nil {
		t.Fatal(err)
	}

	got, err := q.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if got.ID != a.ID {
		t.Fatalf("Next ID=%s want %s", got.ID, a.ID)
	}

	err = q.Finish(got)
	if err != nil {
		t.Fatal(err)
	}

	err = q.Finish(got)
	if err != nil {
		t.Fatalf("second Finish: %v", err)
	}

	messages, bytes := q.Stats()
	if messages != 1 || bytes != 5 {
		t.Fatalf("Stats=(%d, %d) want (1, 5)", messages, bytes)
	}
}

func TestTerminalMovesReconcilePostRenameErrors(t *testing.T) {
	for _, operation := range []string{"finish", "bury"} {

		for _, failure := range []string{"after_rename", "before_source_sync"} {

			t.Run(operation+"/"+failure, func(t *testing.T) {
				clearHooks(t)
				root := t.TempDir()
				q := mustOpen(t, root, Limits{})
				env := testEnv(operation + "-" + failure)
				err := q.Add(env, []byte("body"))
				if err != nil {
					t.Fatal(err)
				}

				got, err := q.Next(context.Background())
				if err != nil {
					t.Fatal(err)
				}

				got.Recipients[0].Status = StatusFailed

				destination := dirTrash
				if operation == "bury" {
					destination = dirDead
				}

				disk.SetHooks(disk.Hooks{
					AfterRename: func(oldpath, newpath string) error {
						if failure == "after_rename" && filepath.Base(filepath.Dir(newpath)) == destination {
							return errors.New("inject after state rename")
						}

						return nil
					},
					BeforeSyncDir: func(path string) error {
						if failure == "before_source_sync" && filepath.Clean(path) == filepath.Join(root, dirReady) {
							return errors.New("inject source sync failure")
						}

						return nil
					},
				})

				if operation == "finish" {
					err = q.Finish(got)
				} else {
					err = q.Bury(got)
				}

				if err == nil {
					t.Fatal("operation should report the injected durability error")
				}

				disk.SetHooks(disk.Hooks{})

				if q.Len() != 0 {
					t.Fatalf("Len=%d want 0", q.Len())
				}

				messages, bytes := q.Stats()
				if messages != 0 || bytes != 0 {
					t.Fatalf("Stats=(%d, %d) want (0, 0)", messages, bytes)
				}

				_, err = os.Stat(filepath.Join(root, dirReady, got.ID))
				if !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("ready entry remains: %v", err)
				}

				if operation == "bury" {
					_, err = os.Stat(filepath.Join(root, dirDead, got.ID, bodyName))
					if err != nil {
						t.Fatalf("dead body: %v", err)
					}

					err = q.Bury(got)
					if err != nil {
						t.Fatalf("idempotent Bury: %v", err)
					}

					if q.Len() != 0 {
						t.Fatalf("idempotent Bury scheduled phantom entry")
					}
				}
			})
		}
	}
}

func TestReviveDeadReservesCapacityAndRollsBack(t *testing.T) {
	clearHooks(t)
	root := t.TempDir()
	q := mustOpen(t, root, Limits{MaxMessages: 1})
	dead := testEnv("revive-dead")
	err := q.Add(dead, []byte("dead"))
	if err != nil {
		t.Fatal(err)
	}

	got, err := q.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	got.Recipients[0].Status = StatusFailed
	got.Recipients[0].Detail = "permanent diagnostic"
	err = q.Bury(got)
	if err != nil {
		t.Fatal(err)
	}

	originalPath := filepath.Join(root, dirDead, dead.ID, metaName)
	original, err := os.ReadFile(originalPath)
	if err != nil {
		t.Fatal(err)
	}

	err = q.Add(testEnv("capacity-holder"), []byte("live"))
	if err != nil {
		t.Fatal(err)
	}

	_, err = q.ReviveDead(dead.ID)
	if !errors.Is(err, ErrQueueFull) {
		t.Fatalf("ReviveDead want ErrQueueFull, got %v", err)
	}

	afterQuota, err := os.ReadFile(originalPath)
	if err != nil {
		t.Fatal(err)
	}

	if string(afterQuota) != string(original) {
		t.Fatal("quota failure changed dead metadata")
	}

	holder, err := q.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	err = q.Finish(holder)
	if err != nil {
		t.Fatal(err)
	}

	disk.SetHooks(disk.Hooks{
		BeforeRename: func(oldpath, newpath string) error {
			if filepath.Clean(oldpath) == filepath.Join(root, dirDead, dead.ID) &&
				filepath.Clean(newpath) == filepath.Join(root, dirReady, dead.ID) {
				return errors.New("inject revive rename failure")
			}

			return nil
		},
	})

	_, err = q.ReviveDead(dead.ID)
	if err == nil {
		t.Fatal("ReviveDead should report rename failure")
	}

	disk.SetHooks(disk.Hooks{})
	afterRename, err := os.ReadFile(originalPath)
	if err != nil {
		t.Fatal(err)
	}

	if string(afterRename) != string(original) {
		t.Fatal("rename failure changed dead metadata")
	}

	messages, bytes := q.Stats()
	if messages != 0 || bytes != 0 {
		t.Fatalf("Stats=(%d, %d) want (0, 0)", messages, bytes)
	}

	revived, err := q.ReviveDead(dead.ID)
	if err != nil {
		t.Fatal(err)
	}

	if revived.Recipients[0].Status != StatusPending || revived.LastError != "" {
		t.Fatalf("unexpected revived envelope: %#v", revived)
	}

	if revived.DSNGeneration != 1 {
		t.Fatalf("revived DSN generation=%d want 1", revived.DSNGeneration)
	}

	if DSNID(revived.ID, revived.Incarnation, revived.DSNGeneration) == DSNID(revived.ID, revived.Incarnation, 0) {
		t.Fatal("revived message retained its prior DSN identity")
	}

	messages, bytes = q.Stats()
	if messages != 1 || bytes != 4 {
		t.Fatalf("Stats=(%d, %d) want (1, 4)", messages, bytes)
	}

	q2 := mustReopen(t, q, root, Limits{MaxMessages: 1})
	if q2.Len() != 1 {
		t.Fatalf("reopened Len=%d want 1", q2.Len())
	}
}

func TestReviveDeadRollsBackActivationFailure(t *testing.T) {
	clearHooks(t)
	root := t.TempDir()
	q := mustOpen(t, root, Limits{})
	env := testEnv("revive-activation-failure")
	err := q.Add(env, []byte("body"))
	if err != nil {
		t.Fatal(err)
	}

	got, err := q.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	got.Recipients[0].Status = StatusFailed
	got.Recipients[0].Detail = "permanent diagnostic"
	err = q.Bury(got)
	if err != nil {
		t.Fatal(err)
	}

	deadDir := filepath.Join(root, dirDead, got.ID)
	original, err := os.ReadFile(filepath.Join(deadDir, metaName))
	if err != nil {
		t.Fatal(err)
	}

	wantErr := errors.New("inject revive activation failure")
	disk.SetHooks(disk.Hooks{BeforeRename: func(oldpath, newpath string) error {
		if filepath.Clean(oldpath) == filepath.Join(root, dirReady, got.ID, reviveMetaName) &&
			filepath.Clean(newpath) == filepath.Join(root, dirReady, got.ID, metaName) {
			return wantErr
		}

		return nil
	}})

	_, err = q.ReviveDead(got.ID)
	if !errors.Is(err, wantErr) {
		t.Fatalf("ReviveDead error=%v, want %v", err, wantErr)
	}

	disk.SetHooks(disk.Hooks{})

	after, err := os.ReadFile(filepath.Join(deadDir, metaName))
	if err != nil {
		t.Fatal(err)
	}

	if string(after) != string(original) {
		t.Fatal("activation failure changed dead metadata")
	}

	_, err = os.Stat(filepath.Join(deadDir, reviveMetaName))
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("staged revive metadata remains: %v", err)
	}

	_, err = os.Stat(filepath.Join(root, dirReady, got.ID))
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("ready entry remains after rollback: %v", err)
	}

	messages, bytes := q.Stats()
	if messages != 0 || bytes != 0 {
		t.Fatalf("Stats=(%d, %d) want (0, 0)", messages, bytes)
	}

	_, err = q.ReviveDead(got.ID)
	if err != nil {
		t.Fatalf("retry ReviveDead: %v", err)
	}
}

func TestReviveDeadReconcilesFailedActivationRollback(t *testing.T) {
	clearHooks(t)
	root := t.TempDir()
	q := mustOpen(t, root, Limits{})
	env := testEnv("revive-rollback-failure")
	err := q.Add(env, []byte("body"))
	if err != nil {
		t.Fatal(err)
	}

	got, err := q.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	got.Recipients[0].Status = StatusFailed
	err = q.Bury(got)
	if err != nil {
		t.Fatal(err)
	}

	activationErr := errors.New("inject activation failure")
	rollbackErr := errors.New("inject rollback failure")
	disk.SetHooks(disk.Hooks{BeforeRename: func(oldpath, newpath string) error {
		switch {
		case filepath.Clean(oldpath) == filepath.Join(root, dirReady, got.ID, reviveMetaName):
			return activationErr
		case filepath.Clean(oldpath) == filepath.Join(root, dirReady, got.ID) &&
			filepath.Clean(newpath) == filepath.Join(root, dirDead, got.ID):
			return rollbackErr
		default:
			return nil
		}
	}})
	revived, err := q.ReviveDead(got.ID)
	if !errors.Is(err, activationErr) || !errors.Is(err, rollbackErr) {
		t.Fatalf("ReviveDead error=%v, want activation and rollback errors", err)
	}

	disk.SetHooks(disk.Hooks{})

	if revived == nil {
		t.Fatal("ReviveDead did not report the reconciled live envelope")
	}

	if q.Len() != 1 {
		t.Fatalf("Len=%d want 1", q.Len())
	}

	messages, bytes := q.Stats()
	if messages != 1 || bytes != 4 {
		t.Fatalf("Stats=(%d, %d) want (1, 4)", messages, bytes)
	}

	queued, err := q.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	err = q.Finish(queued)
	if err != nil {
		t.Fatalf("finish reconciled revive: %v", err)
	}
}

func TestReviveDeadReleasesOwnershipBeforeScheduling(t *testing.T) {
	clearHooks(t)
	q := mustOpen(t, t.TempDir(), Limits{})
	env := testEnv("revive-consumer-handoff")
	err := q.Add(env, []byte("body"))
	if err != nil {
		t.Fatal(err)
	}

	got, err := q.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	got.Recipients[0].Status = StatusFailed
	err = q.Bury(got)
	if err != nil {
		t.Fatal(err)
	}

	published := make(chan struct{})
	release := make(chan struct{})
	q.afterPublish = func() {
		close(published)
		<-release
	}
	result := make(chan error, 1)
	go func() {
		_, err := q.ReviveDead(got.ID)
		result <- err
	}()
	<-published
	revived, err := q.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	err = q.Finish(revived)
	if err != nil {
		t.Fatalf("immediate revived-message consumer: %v", err)
	}

	close(release)

	err = <-result
	if err != nil {
		t.Fatal(err)
	}
}

func TestOpenCompletesInterruptedRevive(t *testing.T) {
	clearHooks(t)
	root := t.TempDir()
	q := mustOpen(t, root, Limits{})
	env := testEnv("revive-crash")
	err := q.Add(env, []byte("body"))
	if err != nil {
		t.Fatal(err)
	}

	got, err := q.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	got.Recipients[0].Status = StatusFailed
	got.Recipients[0].Detail = "permanent"
	got.Attempts = 3
	got.LastError = "failed"
	err = q.Bury(got)
	if err != nil {
		t.Fatal(err)
	}

	got.Recipients[0].Status = StatusPending
	got.Recipients[0].Detail = ""
	got.Attempts = 0
	got.LastError = ""
	deadDir := filepath.Join(root, dirDead, got.ID)
	err = q.writeMeta(filepath.Join(deadDir, reviveMetaName), got)
	if err != nil {
		t.Fatal(err)
	}

	err = os.Rename(deadDir, filepath.Join(root, dirReady, got.ID))
	if err != nil {
		t.Fatal(err)
	}

	q2 := mustReopen(t, q, root, Limits{})
	if q2.Len() != 1 {
		t.Fatalf("Len=%d want 1", q2.Len())
	}

	revived, err := q2.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if revived.Recipients[0].Status != StatusPending || revived.Attempts != 0 || revived.LastError != "" {
		t.Fatalf("interrupted revive not completed: %#v", revived)
	}

	_, err = os.Stat(filepath.Join(root, dirReady, got.ID, reviveMetaName))
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("staged revive metadata remains: %v", err)
	}
}

func TestSameIDTransitionHasSingleOwner(t *testing.T) {
	clearHooks(t)
	root := t.TempDir()
	q := mustOpen(t, root, Limits{})
	env := testEnv("transition-owner")
	err := q.Add(env, []byte("body"))
	if err != nil {
		t.Fatal(err)
	}

	got, err := q.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	got.Recipients[0].Status = StatusFailed

	entered := make(chan struct{})
	release := make(chan struct{})
	disk.SetHooks(disk.Hooks{
		BeforeRename: func(oldpath, newpath string) error {
			if filepath.Clean(oldpath) == filepath.Join(root, dirReady, got.ID) &&
				filepath.Clean(newpath) == filepath.Join(root, dirDead, got.ID) {
				close(entered)
				<-release
			}

			return nil
		},
	})
	done := make(chan error, 1)
	go func() { done <- q.Bury(got) }()
	<-entered

	err = q.Bury(got)
	if !errors.Is(err, ErrQueueBusy) {
		t.Fatalf("concurrent Bury want ErrQueueBusy, got %v", err)
	}

	close(release)

	err = <-done
	if err != nil {
		t.Fatal(err)
	}

	disk.SetHooks(disk.Hooks{})

	if q.Len() != 0 {
		t.Fatalf("Len=%d want 0", q.Len())
	}

	messages, bytes := q.Stats()
	if messages != 0 || bytes != 0 {
		t.Fatalf("Stats=(%d, %d) want (0, 0)", messages, bytes)
	}
}

func TestConcurrentAddNext(t *testing.T) {
	clearHooks(t)
	root := t.TempDir()
	q := mustOpen(t, root, Limits{})

	const n = 50
	var wg sync.WaitGroup
	errCh := make(chan error, n*2)

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := fmt.Sprintf("c%04d", i)
			err := q.Add(testEnv(id), []byte("x"))
			if err != nil {
				errCh <- err
			}
		}(i)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var got atomic.Int32

	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			for {
				if int(got.Load()) >= n {
					return
				}

				e, err := q.Next(ctx)
				if err != nil {
					return
				}

				got.Add(1)
				_ = q.Finish(e)
			}
		}()
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Fatal(err)
	}

	// Drain remaining
	for q.Len() > 0 {
		e, err := q.Next(ctx)
		if err != nil {
			break
		}

		got.Add(1)
		_ = q.Finish(e)
	}

	if int(got.Load()) != n {
		t.Fatalf("got %d want %d", got.Load(), n)
	}
}

func TestQuotaLimits(t *testing.T) {
	clearHooks(t)
	root := t.TempDir()
	q := mustOpen(t, root, Limits{MaxMessages: 1})
	err := q.Add(testEnv("q1"), []byte("a"))
	if err != nil {
		t.Fatal(err)
	}

	err = q.Add(testEnv("q2"), []byte("b"))
	if !errors.Is(err, ErrQueueFull) {
		t.Fatalf("want ErrQueueFull got %v", err)
	}

	root2 := t.TempDir()
	q2 := mustOpen(t, root2, Limits{MaxBytes: 10})
	err = q2.Add(testEnv("b1"), []byte("12345"))
	if err != nil {
		t.Fatal(err)
	}

	err = q2.Add(testEnv("b2"), []byte("1234567890"))
	if !errors.Is(err, ErrQueueFull) {
		t.Fatalf("want ErrQueueFull got %v", err)
	}

	root3 := t.TempDir()
	q3 := mustOpen(t, root3, Limits{MinFreeDisk: 1 << 30})
	q3.FreeDisk = func(string) (int64, error) { return 100, nil }
	err = q3.Add(testEnv("d1"), []byte("x"))
	if !errors.Is(err, ErrInsufficientDisk) {
		t.Fatalf("want ErrInsufficientDisk got %v", err)
	}
}

func TestDSNExemptFromMessageQuota(t *testing.T) {
	clearHooks(t)
	q := mustOpen(t, t.TempDir(), Limits{MaxMessages: 1})
	source := testEnv("ord1")
	err := q.Add(source, []byte("a"))
	if err != nil {
		t.Fatal(err)
	}

	dsn := testDSN(source)
	err = q.AddDSN(source, dsn, []byte("dsn-body"))
	if err != nil {
		t.Fatalf("DSN Add must succeed at MaxMessages: %v", err)
	}

	err = q.Add(testEnv("ord2"), []byte("b"))
	if !errors.Is(err, ErrQueueFull) {
		t.Fatalf("ordinary Add want ErrQueueFull got %v", err)
	}
}

func TestDSNStillSubjectToMinFreeDisk(t *testing.T) {
	clearHooks(t)
	q := mustOpen(t, t.TempDir(), Limits{MinFreeDisk: 1 << 30})
	source := testEnv("dsn-disk-source")
	err := q.Add(source, []byte("source"))
	if err != nil {
		t.Fatal(err)
	}

	q.FreeDisk = func(string) (int64, error) { return 100, nil }
	dsn := testDSN(source)
	err = q.AddDSN(source, dsn, []byte("x"))
	if !errors.Is(err, ErrInsufficientDisk) {
		t.Fatalf("want ErrInsufficientDisk got %v", err)
	}
}

func TestMinFreeDiskIncludesConcurrentReservations(t *testing.T) {
	clearHooks(t)
	q := mustOpen(t, t.TempDir(), Limits{MinFreeDisk: 10})
	entered := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	q.FreeDisk = func(string) (int64, error) {
		if calls.Add(1) == 1 {
			close(entered)
			<-release
		}

		return 100, nil
	}

	first := make(chan error, 1)
	second := make(chan error, 1)
	go func() { first <- q.Reserve(60) }()
	<-entered
	go func() { second <- q.Reserve(40) }()
	close(release)

	err := <-first
	if err != nil {
		t.Fatalf("first Reserve: %v", err)
	}

	err = <-second
	if !errors.Is(err, ErrInsufficientDisk) {
		t.Fatalf("second Reserve error=%v want ErrInsufficientDisk", err)
	}

	q.ReleaseReserve(60)
}

func TestMinFreeDiskIncludesReservationsForExemptDSN(t *testing.T) {
	clearHooks(t)
	q := mustOpen(t, t.TempDir(), Limits{MinFreeDisk: 10})
	source := testEnv("dsn-reserved-disk")
	err := q.Add(source, []byte("source"))
	if err != nil {
		t.Fatal(err)
	}

	q.FreeDisk = func(string) (int64, error) { return 100, nil }
	err = q.Reserve(85)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { q.ReleaseReserve(85) })

	err = q.AddDSN(source, testDSN(source), []byte("123456"))
	if !errors.Is(err, ErrInsufficientDisk) {
		t.Fatalf("AddDSN error=%v want ErrInsufficientDisk", err)
	}
}

func TestDSNIDUsesCompleteSourceIdentity(t *testing.T) {
	prefix := strings.Repeat("a", 180)
	first := prefix + "-first"
	second := prefix + "-second"
	incarnation := strings.Repeat("1", 32)
	firstID := DSNID(first, incarnation, 0)
	secondID := DSNID(second, incarnation, 0)
	if firstID == secondID {
		t.Fatal("long source IDs produced the same DSN ID")
	}

	if firstID == DSNID(first, incarnation, 1) {
		t.Fatal("DSN generation did not affect the ID")
	}

	if firstID == DSNID(first, strings.Repeat("2", 32), 0) {
		t.Fatal("source incarnation did not affect the ID")
	}

	err := ValidateID(firstID)
	if err != nil {
		t.Fatalf("derived ID is invalid: %v", err)
	}
}

func TestAddDSNLinksSourceBeforePublicationAndRecovers(t *testing.T) {
	clearHooks(t)
	root := t.TempDir()
	q := mustOpen(t, root, Limits{})
	source := testEnv("dsn-source-link")
	err := q.Add(source, []byte("source"))
	if err != nil {
		t.Fatal(err)
	}

	_, err = q.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	dsn := testDSN(source)
	wantErr := errors.New("stop before DSN publication")
	observedLink := false
	disk.SetHooks(disk.Hooks{BeforeRename: func(oldpath, newpath string) error {
		if oldpath != filepath.Join(root, dirDSN, dsn.ID) || newpath != filepath.Join(root, dirReady, dsn.ID) {
			return nil
		}

		raw, err := os.ReadFile(filepath.Join(root, dirReady, source.ID, metaName))
		if err != nil {
			t.Fatal(err)
		}

		var linked Envelope

		err = json.Unmarshal(raw, &linked)
		if err != nil {
			t.Fatal(err)
		}

		if linked.DSNID != dsn.ID {
			t.Fatalf("source DSNID=%q before publication, want %q", linked.DSNID, dsn.ID)
		}

		observedLink = true
		return wantErr
	}})

	err = q.AddDSN(source, dsn, []byte("dsn"))
	if !errors.Is(err, wantErr) {
		t.Fatalf("AddDSN error=%v, want %v", err, wantErr)
	}

	if !observedLink {
		t.Fatal("DSN publication was not observed")
	}

	if source.DSNID != "" {
		t.Fatal("failed publication changed caller source state")
	}

	err = q.Finish(source)
	if !errors.Is(err, ErrIDConflict) {
		t.Fatalf("stale Finish error=%v, want ErrIDConflict", err)
	}

	err = q.Bury(source)
	if !errors.Is(err, ErrIDConflict) {
		t.Fatalf("stale Bury error=%v, want ErrIDConflict", err)
	}

	_, err = os.Stat(filepath.Join(root, dirDSN, dsn.ID))
	if err != nil {
		t.Fatalf("linked stage missing: %v", err)
	}

	disk.SetHooks(disk.Hooks{})
	q = mustReopen(t, q, root, Limits{})
	_, err = os.Stat(filepath.Join(root, dirReady, dsn.ID))
	if err != nil {
		t.Fatalf("recovery did not publish DSN: %v", err)
	}

	_, err = os.Stat(filepath.Join(root, dirDSN, dsn.ID))
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stage remains after recovery: %v", err)
	}

	if q.Len() != 2 {
		t.Fatalf("Len=%d want source and DSN", q.Len())
	}
}

func TestOpenQuarantinesUnlinkedDSNStage(t *testing.T) {
	clearHooks(t)
	root := t.TempDir()
	q := mustOpen(t, root, Limits{})
	source := testEnv("dsn-source-orphan")
	err := q.Add(source, []byte("source"))
	if err != nil {
		t.Fatal(err)
	}

	dsn := testDSN(source)
	wantErr := errors.New("stop before source link")
	sourceMeta := filepath.Join(root, dirReady, source.ID, metaName)
	disk.SetHooks(disk.Hooks{BeforeRename: func(_, newpath string) error {
		if newpath == sourceMeta {
			return wantErr
		}

		return nil
	}})

	err = q.AddDSN(source, dsn, []byte("dsn"))
	if !errors.Is(err, wantErr) {
		t.Fatalf("AddDSN error=%v, want %v", err, wantErr)
	}

	_, err = os.Stat(filepath.Join(root, dirDSN, dsn.ID))
	if err != nil {
		t.Fatalf("complete orphan stage missing: %v", err)
	}

	disk.SetHooks(disk.Hooks{})
	q = mustReopen(t, q, root, Limits{})
	_, err = os.Stat(filepath.Join(root, dirReady, dsn.ID))
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("orphan DSN was published: %v", err)
	}

	if q.Len() != 1 {
		t.Fatalf("Len=%d want source only", q.Len())
	}

	if len(q.Corrupt) == 0 || len(corruptEntries(t, root)) == 0 {
		t.Fatal("orphan DSN was not reported and quarantined")
	}
}

func TestAddDSNReconcilesPostRenameError(t *testing.T) {
	clearHooks(t)
	root := t.TempDir()
	q := mustOpen(t, root, Limits{})
	source := testEnv("dsn-source-moved")
	err := q.Add(source, []byte("source"))
	if err != nil {
		t.Fatal(err)
	}

	_, err = q.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	dsn := testDSN(source)
	wantErr := errors.New("after DSN rename")
	disk.SetHooks(disk.Hooks{AfterRename: func(oldpath, newpath string) error {
		if oldpath == filepath.Join(root, dirDSN, dsn.ID) && newpath == filepath.Join(root, dirReady, dsn.ID) {
			return wantErr
		}

		return nil
	}})

	err = q.AddDSN(source, dsn, []byte("dsn"))
	if !errors.Is(err, wantErr) {
		t.Fatalf("AddDSN error=%v, want %v", err, wantErr)
	}

	if source.DSNID != dsn.ID {
		t.Fatalf("source DSNID=%q want %q", source.DSNID, dsn.ID)
	}

	if q.Len() != 1 {
		t.Fatalf("Len=%d want published DSN", q.Len())
	}

	got, err := q.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if got.ID != dsn.ID {
		t.Fatalf("scheduled %s want %s", got.ID, dsn.ID)
	}
}

func TestAddDSNReleasesOwnershipBeforeScheduling(t *testing.T) {
	clearHooks(t)
	q := mustOpen(t, t.TempDir(), Limits{})
	source := testEnv("dsn-consumer-handoff")
	err := q.Add(source, []byte("source"))
	if err != nil {
		t.Fatal(err)
	}

	_, err = q.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	published := make(chan struct{})
	release := make(chan struct{})
	q.afterPublish = func() {
		close(published)
		<-release
	}
	result := make(chan error, 1)
	go func() {
		result <- q.AddDSN(source, testDSN(source), []byte("dsn"))
	}()
	<-published
	dsn, err := q.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	err = q.Finish(dsn)
	if err != nil {
		t.Fatalf("immediate DSN consumer: %v", err)
	}

	close(release)

	err = <-result
	if err != nil {
		t.Fatal(err)
	}
}

func TestAddReleasesOwnershipBeforeScheduling(t *testing.T) {
	clearHooks(t)
	q := mustOpen(t, t.TempDir(), Limits{})
	published := make(chan struct{})
	release := make(chan struct{})
	q.afterPublish = func() {
		close(published)
		<-release
	}
	result := make(chan error, 1)
	env := testEnv("add-consumer-handoff")
	go func() {
		result <- q.Add(env, []byte("body"))
	}()
	<-published
	got, err := q.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	err = q.Finish(got)
	if err != nil {
		t.Fatalf("immediate added-message consumer: %v", err)
	}

	close(release)

	err = <-result
	if err != nil {
		t.Fatal(err)
	}
}

func TestAddRejectsOccupiedReadyID(t *testing.T) {
	for _, checkedOut := range []bool{false, true} {

		t.Run(fmt.Sprintf("checked_out_%t", checkedOut), func(t *testing.T) {
			clearHooks(t)
			q := mustOpen(t, t.TempDir(), Limits{})
			original := testEnv("occupied-add-id")
			err := q.Add(original, []byte("original"))
			if err != nil {
				t.Fatal(err)
			}

			if checkedOut {
				_, err := q.Next(context.Background())
				if err != nil {
					t.Fatal(err)
				}
			}

			err = q.Add(testEnv(original.ID), []byte("replacement"))
			if !errors.Is(err, ErrIDConflict) {
				t.Fatalf("Add error=%v, want ErrIDConflict", err)
			}

			body, err := q.ReadBody(original.ID)
			if err != nil {
				t.Fatal(err)
			}

			if string(body) != "original" {
				t.Fatalf("body=%q want original", body)
			}

			messages, bytes := q.Stats()
			if messages != 1 || bytes != int64(len("original")) {
				t.Fatalf("Stats=(%d, %d) want (1, %d)", messages, bytes, len("original"))
			}
		})
	}
}

func TestAddReconcilesPriorUncommittedReadyEntry(t *testing.T) {
	clearHooks(t)
	root := t.TempDir()
	q := mustOpen(t, root, Limits{})
	env := testEnv("retry-uncommitted-add")
	wantErr := errors.New("inject post-rename add failure")
	disk.SetHooks(disk.Hooks{AfterRename: func(oldpath, newpath string) error {
		if filepath.Clean(oldpath) == filepath.Join(root, dirTmp, env.ID) &&
			filepath.Clean(newpath) == filepath.Join(root, dirReady, env.ID) {
			return wantErr
		}

		return nil
	}})

	err := q.Add(env, []byte("first"))
	if !errors.Is(err, wantErr) {
		t.Fatalf("Add error=%v, want %v", err, wantErr)
	}

	disk.SetHooks(disk.Hooks{})

	err = q.Add(env, []byte("retry"))
	if err != nil {
		t.Fatalf("same-process Add retry: %v", err)
	}

	got, err := q.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	body, err := q.ReadBody(got.ID)
	if err != nil {
		t.Fatal(err)
	}

	if string(body) != "retry" {
		t.Fatalf("body=%q want retry", body)
	}
}

func TestAddDoesNotQuarantineUnreadableReadyState(t *testing.T) {
	clearHooks(t)
	root := t.TempDir()
	q := mustOpen(t, root, Limits{})
	env := testEnv("unreadable-ready-state")
	env.Size = int64(len("original"))
	readyDir := filepath.Join(root, dirReady, env.ID)
	err := disk.Mkdir(readyDir)
	if err != nil {
		t.Fatal(err)
	}

	err = q.writeMeta(filepath.Join(readyDir, metaName), env)
	if err != nil {
		t.Fatal(err)
	}

	err = disk.Write(filepath.Join(readyDir, bodyName), []byte("original"), 0600)
	if err != nil {
		t.Fatal(err)
	}

	writeAcceptedMarker(t, readyDir)
	statePath := filepath.Join(readyDir, addStateName)
	err = os.Remove(statePath)
	if err != nil {
		t.Fatal(err)
	}

	err = os.Mkdir(statePath, 0700)
	if err != nil {
		t.Fatal(err)
	}

	err = q.Add(testEnv(env.ID), []byte("replacement"))
	if err == nil {
		t.Fatal("Add should report unreadable ready state")
	}

	_, err = os.Stat(filepath.Join(root, dirReady, env.ID, bodyName))
	if err != nil {
		t.Fatalf("accepted ready entry was moved: %v", err)
	}

	err = os.RemoveAll(statePath)
	if err != nil {
		t.Fatal(err)
	}

	writeAcceptedMarker(t, readyDir)
	body, err := q.ReadBody(env.ID)
	if err != nil {
		t.Fatal(err)
	}

	if string(body) != "original" {
		t.Fatalf("body=%q want original", body)
	}
}

func TestAddRejectsDeadID(t *testing.T) {
	clearHooks(t)
	q := mustOpen(t, t.TempDir(), Limits{})
	env := testEnv("occupied-dead-id")
	err := q.Add(env, []byte("original"))
	if err != nil {
		t.Fatal(err)
	}

	got, err := q.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	got.Recipients[0].Status = StatusFailed
	err = q.Bury(got)
	if err != nil {
		t.Fatal(err)
	}

	err = q.Add(testEnv(env.ID), []byte("replacement"))
	if !errors.Is(err, ErrIDConflict) {
		t.Fatalf("Add error=%v, want ErrIDConflict", err)
	}

	body, err := q.ReadBody(env.ID)
	if err != nil {
		t.Fatal(err)
	}

	if string(body) != "original" {
		t.Fatalf("dead body=%q want original", body)
	}
}

func TestRequeueDoesNotPublishDuringTransition(t *testing.T) {
	clearHooks(t)
	root := t.TempDir()
	q := mustOpen(t, root, Limits{})
	env := testEnv("requeue-transition")
	err := q.Add(env, []byte("body"))
	if err != nil {
		t.Fatal(err)
	}

	got, err := q.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	entered := make(chan struct{})
	release := make(chan struct{})
	disk.SetHooks(disk.Hooks{BeforeRename: func(oldpath, newpath string) error {
		if filepath.Clean(newpath) == filepath.Join(root, dirReady, got.ID, metaName) {
			close(entered)
			<-release
		}

		return nil
	}})
	result := make(chan error, 1)
	go func() {
		result <- q.Retry(got)
	}()
	<-entered
	q.Requeue(got)

	if q.Len() != 0 {
		t.Fatalf("Len=%d want no publication during transition", q.Len())
	}

	close(release)

	err = <-result
	if err != nil {
		t.Fatal(err)
	}

	disk.SetHooks(disk.Hooks{})

	if q.Len() != 1 {
		t.Fatalf("Len=%d want retried message", q.Len())
	}
}

func TestRequeueIntentSurvivesFailedTransition(t *testing.T) {
	clearHooks(t)
	root := t.TempDir()
	q := mustOpen(t, root, Limits{})
	env := testEnv("requeue-failed-transition")
	err := q.Add(env, []byte("body"))
	if err != nil {
		t.Fatal(err)
	}

	got, err := q.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	entered := make(chan struct{})
	release := make(chan struct{})
	wantErr := errors.New("inject finish failure")
	disk.SetHooks(disk.Hooks{BeforeRename: func(oldpath, newpath string) error {
		if filepath.Clean(oldpath) == filepath.Join(root, dirReady, got.ID) &&
			filepath.Clean(filepath.Dir(newpath)) == filepath.Join(root, dirTrash) {
			close(entered)
			<-release
			return wantErr
		}

		return nil
	}})
	result := make(chan error, 1)
	go func() {
		result <- q.Finish(got)
	}()
	<-entered
	got.Recipients[0].Detail = "before deferred requeue"
	q.Requeue(got)
	got.Recipients[0].Detail = "after deferred requeue"
	if q.Len() != 0 {
		t.Fatalf("Len=%d want deferred requeue", q.Len())
	}

	close(release)

	err = <-result
	if !errors.Is(err, wantErr) {
		t.Fatalf("Finish error=%v, want %v", err, wantErr)
	}

	disk.SetHooks(disk.Hooks{})

	if q.Len() != 1 {
		t.Fatalf("Len=%d want preserved requeue intent", q.Len())
	}

	requeued, err := q.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if requeued.Recipients[0].Detail != "before deferred requeue" {
		t.Fatalf("deferred requeue retained caller recipients: %#v", requeued.Recipients)
	}

	err = q.Finish(requeued)
	if err != nil {
		t.Fatal(err)
	}
}

func TestBuryFailureReleasesOwnershipBeforeRescheduling(t *testing.T) {
	clearHooks(t)
	root := t.TempDir()
	q := mustOpen(t, root, Limits{})
	env := testEnv("bury-consumer-handoff")
	err := q.Add(env, []byte("body"))
	if err != nil {
		t.Fatal(err)
	}

	got, err := q.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	got.Recipients[0].Status = StatusFailed
	wantErr := errors.New("inject post-rename bury metadata error")
	disk.SetHooks(disk.Hooks{AfterRename: func(oldpath, newpath string) error {
		if filepath.Clean(newpath) == filepath.Join(root, dirReady, got.ID, metaName) {
			return wantErr
		}

		return nil
	}})
	published := make(chan struct{})
	release := make(chan struct{})
	q.afterPublish = func() {
		close(published)
		<-release
	}
	result := make(chan error, 1)
	go func() {
		result <- q.Bury(got)
	}()
	<-published
	disk.SetHooks(disk.Hooks{})
	q.afterPublish = nil
	requeued, err := q.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	err = q.Finish(requeued)
	if err != nil {
		t.Fatalf("immediate consumer after Bury failure: %v", err)
	}

	close(release)

	err = <-result
	if !errors.Is(err, wantErr) {
		t.Fatalf("Bury error=%v, want %v", err, wantErr)
	}
}

func TestAddDSNRejectsExistingDifferentIdentity(t *testing.T) {
	clearHooks(t)
	q := mustOpen(t, t.TempDir(), Limits{})
	source := testEnv("dsn-source-conflict")
	err := q.Add(source, []byte("source"))
	if err != nil {
		t.Fatal(err)
	}

	dsn := testDSN(source)
	occupant := testEnv(dsn.ID)
	err = q.Add(occupant, []byte("occupant"))
	if err != nil {
		t.Fatal(err)
	}

	err = q.AddDSN(source, dsn, []byte("dsn"))
	if !errors.Is(err, ErrIDConflict) {
		t.Fatalf("AddDSN error=%v, want ErrIDConflict", err)
	}
}

func TestStaleHandleCannotMutateReplacement(t *testing.T) {
	for _, operation := range []string{"retry", "finish", "bury", "dsn"} {

		t.Run(operation, func(t *testing.T) {
			clearHooks(t)
			q := mustOpen(t, t.TempDir(), Limits{})
			stale := testEnv("reused-id")
			err := q.Add(stale, []byte("old"))
			if err != nil {
				t.Fatal(err)
			}

			_, err = q.Next(context.Background())
			if err != nil {
				t.Fatal(err)
			}

			err = q.Finish(stale)
			if err != nil {
				t.Fatal(err)
			}

			replacement := testEnv("reused-id")
			err = q.Add(replacement, []byte("replacement"))
			if err != nil {
				t.Fatal(err)
			}

			if stale.Incarnation == replacement.Incarnation {
				t.Fatal("replacement reused the old incarnation")
			}

			switch operation {
			case "retry":
				err = q.Retry(stale)
			case "finish":
				err = q.Finish(stale)
			case "bury":
				stale.Recipients[0].Status = StatusFailed
				err = q.Bury(stale)
			case "dsn":
				stale.Recipients[0].Status = StatusFailed
				err = q.AddDSN(stale, testDSN(stale), []byte("dsn"))
			}

			if !errors.Is(err, ErrIDConflict) {
				t.Fatalf("%s error=%v, want ErrIDConflict", operation, err)
			}

			body, readErr := q.ReadBody(replacement.ID)
			if readErr != nil || string(body) != "replacement" {
				t.Fatalf("replacement changed: body=%q err=%v", body, readErr)
			}

			if q.Len() != 1 {
				t.Fatalf("Len=%d want replacement only", q.Len())
			}
		})
	}
}

func TestRequeueIsIdempotentAndRejectsStaleRevision(t *testing.T) {
	clearHooks(t)
	q := mustOpen(t, t.TempDir(), Limits{})
	env := testEnv("requeue-owner")
	err := q.Add(env, []byte("body"))
	if err != nil {
		t.Fatal(err)
	}

	got, err := q.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	q.Requeue(got)
	q.Requeue(got)

	if q.Len() != 1 {
		t.Fatalf("duplicate Requeue Len=%d want 1", q.Len())
	}

	got, err = q.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	stale := *got
	got.Attempts++
	got.NextAttempt = time.Now()
	err = q.Retry(got)
	if err != nil {
		t.Fatal(err)
	}

	q.Requeue(&stale)

	if q.Len() != 1 {
		t.Fatalf("stale Requeue Len=%d want current revision only", q.Len())
	}
}

func TestAddDSNRejectsStaleSourceRevision(t *testing.T) {
	clearHooks(t)
	q := mustOpen(t, t.TempDir(), Limits{})
	source := testEnv("dsn-stale-revision")
	err := q.Add(source, []byte("source"))
	if err != nil {
		t.Fatal(err)
	}

	stale := *source
	_, err = q.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	source.Attempts++
	source.NextAttempt = time.Now().Add(time.Minute)
	err = q.Retry(source)
	if err != nil {
		t.Fatal(err)
	}

	stale.Recipients = append([]Recipient(nil), stale.Recipients...)
	stale.Recipients[0].Status = StatusFailed
	err = q.AddDSN(&stale, testDSN(&stale), []byte("dsn"))
	if !errors.Is(err, ErrIDConflict) {
		t.Fatalf("AddDSN error=%v, want ErrIDConflict", err)
	}

	_, err = os.Stat(filepath.Join(q.dsn, DSNID(stale.ID, stale.Incarnation, stale.DSNGeneration)))
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale AddDSN created a stage: %v", err)
	}
}

func TestOpenExclusiveLock(t *testing.T) {
	clearHooks(t)
	root := t.TempDir()
	q1 := mustOpen(t, root, Limits{})
	_, err := Open(root, Limits{})
	if !errors.Is(err, disk.ErrLocked) {
		t.Fatalf("second Open want ErrLocked got %v", err)
	}

	err = q1.Close()
	if err != nil {
		t.Fatal(err)
	}

	q2, err := Open(root, Limits{})
	if err != nil {
		t.Fatalf("Open after Close: %v", err)
	}

	t.Cleanup(func() { _ = q2.Close() })
}

func TestOpenReadOnlyAlongsideLocked(t *testing.T) {
	clearHooks(t)
	root := t.TempDir()
	q := mustOpen(t, root, Limits{})

	// Seed a dead-letter entry.
	now := time.Now().UTC().Truncate(time.Second)
	env := testEnv("dead1")
	body := []byte("From: a\r\nTo: b\r\n\r\nbody\r\n")
	err := q.Add(env, body)
	if err != nil {
		t.Fatal(err)
	}

	got, err := q.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	got.Recipients[0].Status = StatusFailed
	got.Recipients[0].Detail = "gone"
	got.LastError = "gone"
	got.Created = now
	err = q.Bury(got)
	if err != nil {
		t.Fatal(err)
	}

	ro, err := OpenReadOnly(root)
	if err != nil {
		t.Fatal(err)
	}

	ids, err := ro.DeadIDs()
	if err != nil {
		t.Fatal(err)
	}

	if len(ids) != 1 || ids[0] != "dead1" {
		t.Fatalf("DeadIDs=%v", ids)
	}

	loaded, err := ro.LoadDead("dead1")
	if err != nil {
		t.Fatal(err)
	}

	if loaded.ID != "dead1" {
		t.Fatalf("LoadDead id=%s", loaded.ID)
	}

	err = ro.Add(testEnv("x"), []byte("y"))
	if !errors.Is(err, ErrReadOnly) {
		t.Fatalf("Add want ErrReadOnly got %v", err)
	}

	err = ro.Reserve(1)
	if !errors.Is(err, ErrReadOnly) {
		t.Fatalf("Reserve want ErrReadOnly got %v", err)
	}
}

func TestCorruptNeverDeletedSilently(t *testing.T) {
	clearHooks(t)
	root := t.TempDir()
	_ = mustOpen(t, root, Limits{}).Close()

	// Seed several corrupt ready dirs.
	for i, name := range []string{"c1", "c2", "c3"} {

		dir := filepath.Join(root, dirReady, name)
		err := os.MkdirAll(dir, 0700)
		if err != nil {
			t.Fatal(err)
		}

		switch i {
		case 0:
			_ = os.WriteFile(filepath.Join(dir, metaName), []byte("{"), 0600)
			_ = os.WriteFile(filepath.Join(dir, bodyName), []byte("x"), 0600)
		case 1:
			env := testEnv(name)
			raw, _ := json.Marshal(env)
			_ = os.WriteFile(filepath.Join(dir, metaName), raw, 0600)

			// no body
		case 2:
			_ = os.WriteFile(filepath.Join(dir, bodyName), []byte("only"), 0600)
		}

		writeAcceptedMarker(t, dir)
	}

	q := mustOpen(t, root, Limits{})
	corr := corruptEntries(t, root)
	if len(corr) < 3 {
		t.Fatalf("expected >=3 quarantine entries, got %v corrupt=%v", corr, q.Corrupt)
	}

	if len(q.Corrupt) < 3 {
		t.Fatalf("Corrupt events %d want >=3: %v", len(q.Corrupt), q.Corrupt)
	}

	// Nothing left unread under ready with those names.
	for _, name := range []string{"c1", "c2", "c3"} {

		_, err := os.Stat(filepath.Join(root, dirReady, name))
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s still in ready (not quarantined)", name)
		}
	}
}

func TestSMTPUTF8EnvelopeInvariant(t *testing.T) {
	clearHooks(t)
	q := mustOpen(t, t.TempDir(), Limits{})
	now := time.Now().UTC().Truncate(time.Second)
	body := []byte("From: a@ex.com\r\nTo: b@ex.com\r\nSubject: t\r\n\r\nHi\r\n")

	// UTF-8 sender without flag rejected.
	err := q.Add(&Envelope{
		ID: "u1", Username: "u", Sender: "björn@ex.com",
		Recipients:  []Recipient{{Address: "b@ex.com", Domain: "ex.com", Status: StatusPending}},
		Created:     now,
		NextAttempt: now,
		SMTPUTF8:    false,
	}, body)
	if err == nil {
		t.Fatal("UTF-8 sender without SMTPUTF8 must reject")
	}

	// UTF-8 recipient without flag rejected.
	err = q.Add(&Envelope{
		ID: "u2", Username: "u", Sender: "a@ex.com",
		Recipients:  []Recipient{{Address: "björn@ex.com", Domain: "ex.com", Status: StatusPending}},
		Created:     now,
		NextAttempt: now,
		SMTPUTF8:    false,
	}, body)
	if err == nil {
		t.Fatal("UTF-8 recipient without SMTPUTF8 must reject")
	}

	// UTF-8 with flag accepted.
	err = q.Add(&Envelope{
		ID: "u3", Username: "u", Sender: "björn@ex.com",
		Recipients:  []Recipient{{Address: "åke@ex.com", Domain: "ex.com", Status: StatusPending}},
		Created:     now,
		NextAttempt: now,
		SMTPUTF8:    true,
	}, body)
	if err != nil {
		t.Fatal(err)
	}

	// ASCII with SMTPUTF8 false accepted.
	err = q.Add(&Envelope{
		ID: "uip4", Username: "u", Sender: "a@ex.com",
		Recipients:  []Recipient{{Address: "b@ex.com", Domain: "ex.com", Status: StatusPending}},
		Created:     now,
		NextAttempt: now,
		SMTPUTF8:    false,
	}, body)
	if err != nil {
		t.Fatal(err)
	}

	// ASCII with SMTPUTF8 true accepted (headers may require it).
	err = q.Add(&Envelope{
		ID: "u5", Username: "u", Sender: "a@ex.com",
		Recipients:  []Recipient{{Address: "b@ex.com", Domain: "ex.com", Status: StatusPending}},
		Created:     now,
		NextAttempt: now,
		SMTPUTF8:    true,
	}, body)
	if err != nil {
		t.Fatal(err)
	}

	// Null sender DSN with ASCII recipient, no SMTPUTF8.
	source6 := testEnv("source-u6")
	err = q.Add(source6, body)
	if err != nil {
		t.Fatal(err)
	}

	err = q.AddDSN(source6, &Envelope{
		ID: DSNID(source6.ID, source6.Incarnation, 0), Username: "u", Sender: "", DSNSourceID: source6.ID, DSNSourceIncarnation: source6.Incarnation,
		Recipients:  []Recipient{{Address: "b@ex.com", Domain: "ex.com", Status: StatusPending}},
		Created:     now,
		NextAttempt: now,
		SMTPUTF8:    false,
	}, body)
	if err != nil {
		t.Fatal(err)
	}

	// Null sender DSN with UTF-8 recipient requires SMTPUTF8.
	source7 := testEnv("source-u7")
	err = q.Add(source7, body)
	if err != nil {
		t.Fatal(err)
	}

	err = q.AddDSN(source7, &Envelope{
		ID: DSNID(source7.ID, source7.Incarnation, 0), Username: "u", Sender: "", DSNSourceID: source7.ID, DSNSourceIncarnation: source7.Incarnation,
		Recipients:  []Recipient{{Address: "björn@ex.com", Domain: "ex.com", Status: StatusPending}},
		Created:     now,
		NextAttempt: now,
		SMTPUTF8:    false,
	}, body)
	if err == nil {
		t.Fatal("DSN UTF-8 recipient without SMTPUTF8 must reject")
	}

	source8 := testEnv("source-u8")
	err = q.Add(source8, body)
	if err != nil {
		t.Fatal(err)
	}

	err = q.AddDSN(source8, &Envelope{
		ID: DSNID(source8.ID, source8.Incarnation, 0), Username: "u", Sender: "", DSNSourceID: source8.ID, DSNSourceIncarnation: source8.Incarnation,
		Recipients:  []Recipient{{Address: "björn@ex.com", Domain: "ex.com", Status: StatusPending}},
		Created:     now,
		NextAttempt: now,
		SMTPUTF8:    true,
	}, body)
	if err != nil {
		t.Fatal(err)
	}
}

func TestSMTPUTF8InvariantOpenQuarantine(t *testing.T) {
	clearHooks(t)
	root := t.TempDir()
	_ = mustOpen(t, root, Limits{}).Close()
	now := time.Now().UTC().Truncate(time.Second)

	// Write a ready entry that bypasses Add validation.
	dir := filepath.Join(root, dirReady, "badutf8")
	err := os.MkdirAll(dir, 0700)
	if err != nil {
		t.Fatal(err)
	}

	env := &Envelope{
		ID: "badutf8", Username: "u", Sender: "björn@ex.com",
		Recipients:  []Recipient{{Address: "b@ex.com", Domain: "ex.com", Status: StatusPending}},
		Created:     now,
		NextAttempt: now,
		SMTPUTF8:    false,
	}
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile(filepath.Join(dir, metaName), raw, 0600)
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile(filepath.Join(dir, bodyName), []byte("From: x\r\n\r\n"), 0600)
	if err != nil {
		t.Fatal(err)
	}

	writeAcceptedMarker(t, dir)
	q := mustOpen(t, root, Limits{})
	_, err = os.Stat(dir)
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatal("violating ready entry must be quarantined on Open")
	}

	if len(corruptEntries(t, root)) == 0 && len(q.Corrupt) == 0 {
		t.Fatal("expected quarantine/corrupt report")
	}

	if q.Len() != 0 {
		t.Fatal("must not schedule violating entry")
	}
}

func TestOpenQuarantinesBodySizeMismatch(t *testing.T) {
	for _, tc := range []bodySizeMismatchCase{
		{name: "smaller", metadata: 1, body: []byte("body")},
		{name: "larger", metadata: 10, body: []byte("body")},
		{name: "zero", metadata: 0, body: []byte("body")},
		{name: "nonzero_empty", metadata: 1, body: nil},
	} {

		t.Run(tc.name, func(t *testing.T) {
			clearHooks(t)
			root := t.TempDir()
			_ = mustOpen(t, root, Limits{}).Close()
			env := testEnv("size-" + tc.name)
			env.Size = tc.metadata
			dir := writeQueueEntry(t, root, dirReady, env, tc.body)

			q := mustOpen(t, root, Limits{})
			if q.Len() != 0 {
				t.Fatalf("Len=%d want 0", q.Len())
			}

			messages, bytes := q.Stats()
			if messages != 0 || bytes != 0 {
				t.Fatalf("Stats=(%d, %d) want (0, 0)", messages, bytes)
			}

			_, err := os.Stat(dir)
			if !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("mismatched entry remains ready: %v", err)
			}

			if len(q.Corrupt) == 0 || len(corruptEntries(t, root)) == 0 {
				t.Fatal("size mismatch was not reported and quarantined")
			}
		})
	}
}

func TestDeadBodySizeMismatchIsRejected(t *testing.T) {
	clearHooks(t)
	root := t.TempDir()
	q := mustOpen(t, root, Limits{})
	env := testEnv("dead-size-mismatch")
	env.Size = 1
	writeQueueEntry(t, root, dirDead, env, []byte("body"))

	_, err := q.LoadDead(env.ID)
	if err == nil || !strings.Contains(err.Error(), "body size mismatch") {
		t.Fatalf("LoadDead error=%v", err)
	}

	_, err = q.ReviveDead(env.ID)
	if err == nil || !strings.Contains(err.Error(), "body size mismatch") {
		t.Fatalf("ReviveDead error=%v", err)
	}

	err = q.ExportDead(env.ID, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "body size mismatch") {
		t.Fatalf("ExportDead error=%v", err)
	}

	_, err = q.ReadBody(env.ID)
	if err == nil || !strings.Contains(err.Error(), "body size mismatch") {
		t.Fatalf("ReadBody error=%v", err)
	}

	_, err = os.Stat(filepath.Join(root, dirDead, env.ID, bodyName))
	if err != nil {
		t.Fatalf("dead entry changed: %v", err)
	}
}

func TestAddAccountsActualBodySize(t *testing.T) {
	clearHooks(t)
	q := mustOpen(t, t.TempDir(), Limits{})
	env := testEnv("actual-size")
	env.Size = 999
	body := []byte("actual")
	err := q.Add(env, body)
	if err != nil {
		t.Fatal(err)
	}

	if env.Size != int64(len(body)) {
		t.Fatalf("Size=%d want %d", env.Size, len(body))
	}

	messages, bytes := q.Stats()
	if messages != 1 || bytes != int64(len(body)) {
		t.Fatalf("Stats=(%d, %d)", messages, bytes)
	}
}

func TestBuryRejectsDeadIDCollisionWithoutMutation(t *testing.T) {
	clearHooks(t)
	root := t.TempDir()
	q := mustOpen(t, root, Limits{})
	env := testEnv("bury-collision")
	err := q.Add(env, []byte("ready body"))
	if err != nil {
		t.Fatal(err)
	}

	got, err := q.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	got.Recipients[0].Status = StatusFailed
	dead := testEnv(got.ID)
	dead.Incarnation = strings.Repeat("1", 32)
	dead.Size = int64(len("dead body"))
	deadDir := writeQueueEntry(t, root, dirDead, dead, []byte("dead body"))
	beforeMeta, err := os.ReadFile(filepath.Join(deadDir, metaName))
	if err != nil {
		t.Fatal(err)
	}

	err = q.Bury(got)
	if !errors.Is(err, ErrIDConflict) {
		t.Fatalf("Bury error=%v want ErrIDConflict", err)
	}

	readyBody, err := os.ReadFile(filepath.Join(root, dirReady, got.ID, bodyName))
	if err != nil || string(readyBody) != "ready body" {
		t.Fatalf("ready body=%q err=%v", readyBody, err)
	}

	afterMeta, err := os.ReadFile(filepath.Join(deadDir, metaName))
	if err != nil || string(afterMeta) != string(beforeMeta) {
		t.Fatalf("dead metadata changed: %v", err)
	}

	entries, err := os.ReadDir(filepath.Join(root, dirDead))
	if err != nil {
		t.Fatal(err)
	}

	if len(entries) != 1 || entries[0].Name() != got.ID {
		t.Fatalf("dead entries=%v", entries)
	}

	if q.Len() != 1 {
		t.Fatalf("ready item was not rescheduled, Len=%d", q.Len())
	}
}

func TestBuryMissingReadyRequiresMatchingDeadIdentity(t *testing.T) {
	clearHooks(t)
	root := t.TempDir()
	q := mustOpen(t, root, Limits{})
	dead := testEnv("bury-stale")
	dead.Size = 4
	writeQueueEntry(t, root, dirDead, dead, []byte("body"))
	stale := *dead
	stale.Incarnation = strings.Repeat("2", 32)
	err := q.Bury(&stale)
	if !errors.Is(err, ErrIDConflict) {
		t.Fatalf("Bury error=%v want ErrIDConflict", err)
	}
}

func TestOpenQuarantinesReadyDeadCollision(t *testing.T) {
	clearHooks(t)
	root := t.TempDir()
	q := mustOpen(t, root, Limits{})
	ready := testEnv("open-dead-collision")
	err := q.Add(ready, []byte("ready"))
	if err != nil {
		t.Fatal(err)
	}

	err = q.Close()
	if err != nil {
		t.Fatal(err)
	}

	dead := testEnv(ready.ID)
	dead.Incarnation = strings.Repeat("3", 32)
	dead.Size = 4
	deadDir := writeQueueEntry(t, root, dirDead, dead, []byte("dead"))

	q2, err := Open(root, Limits{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	t.Cleanup(func() { _ = q2.Close() })

	if q2.Len() != 0 {
		t.Fatalf("conflicting ID was scheduled: Len=%d", q2.Len())
	}

	if len(q2.Corrupt) == 0 || !strings.Contains(q2.Corrupt[0].Error(), "BLOCKED") {
		t.Fatalf("conflict was not prominently reported: %v", q2.Corrupt)
	}

	_, err = os.Stat(deadDir)
	if err != nil {
		t.Fatalf("dead entry changed: %v", err)
	}

	_, err = os.Stat(filepath.Join(root, dirReady, ready.ID))
	if err != nil {
		t.Fatalf("ready entry changed: %v", err)
	}
}

func TestOpenQuarantinesInvalidDeadCollisionAndLoadsReady(t *testing.T) {
	clearHooks(t)
	root := t.TempDir()
	q := mustOpen(t, root, Limits{})
	env := testEnv("invalid-dead-collision")
	err := q.Add(env, []byte("ready"))
	if err != nil {
		t.Fatal(err)
	}

	err = q.Close()
	if err != nil {
		t.Fatal(err)
	}

	deadDir := filepath.Join(root, dirDead, env.ID)
	err = os.Mkdir(deadDir, 0700)
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile(filepath.Join(deadDir, metaName), []byte("{"), 0600)
	if err != nil {
		t.Fatal(err)
	}

	q2 := mustOpen(t, root, Limits{})
	if q2.Len() != 1 {
		t.Fatalf("Len=%d want 1", q2.Len())
	}

	if len(q2.Corrupt) == 0 || len(corruptEntries(t, root)) == 0 {
		t.Fatal("invalid dead entry was not quarantined")
	}
}

func TestDeadIDsAllowsBakSubstring(t *testing.T) {
	clearHooks(t)
	root := t.TempDir()
	q := mustOpen(t, root, Limits{})
	err := os.Mkdir(filepath.Join(root, dirDead, "real.bak.id"), 0700)
	if err != nil {
		t.Fatal(err)
	}

	ids, err := q.DeadIDs()
	if err != nil {
		t.Fatal(err)
	}

	if len(ids) != 1 || ids[0] != "real.bak.id" {
		t.Fatalf("DeadIDs=%v", ids)
	}
}

func TestTrashCleanupReportsAndRetriesFailure(t *testing.T) {
	clearHooks(t)
	root := t.TempDir()
	q := mustOpen(t, root, Limits{})
	trashEntry := filepath.Join(root, dirTrash, "leftover")
	err := os.Mkdir(trashEntry, 0700)
	if err != nil {
		t.Fatal(err)
	}

	err = q.Close()
	if err != nil {
		t.Fatal(err)
	}

	wantErr := errors.New("remove trash")
	syncAttempted := false
	disk.SetHooks(disk.Hooks{BeforeRemoveAll: func(path string) error {
		if filepath.Clean(path) == filepath.Clean(trashEntry) {
			return wantErr
		}

		return nil
	}, BeforeSyncDir: func(path string) error {
		if filepath.Clean(path) == filepath.Join(root, dirTrash) {
			syncAttempted = true
		}

		return nil
	}})
	q2, err := Open(root, Limits{})
	if err != nil {
		t.Fatal(err)
	}

	if len(q2.Warnings) != 1 || !errors.Is(q2.Warnings[0], wantErr) {
		t.Fatalf("Warnings=%v want %v", q2.Warnings, wantErr)
	}

	if !syncAttempted {
		t.Fatal("trash directory was not synced after removal failure")
	}

	_, err = os.Stat(trashEntry)
	if err != nil {
		t.Fatalf("failed trash entry removed: %v", err)
	}

	err = q2.Close()
	if err != nil {
		t.Fatal(err)
	}

	disk.SetHooks(disk.Hooks{})
	q3 := mustOpen(t, root, Limits{})
	entries, err := os.ReadDir(q3.trash)
	if err != nil || len(entries) != 0 {
		t.Fatalf("trash entries=%v err=%v", entries, err)
	}
}

func TestFinishReportsTrashSyncFailureAfterRemoval(t *testing.T) {
	clearHooks(t)
	root := t.TempDir()
	q := mustOpen(t, root, Limits{})
	env := testEnv("finish-sync-error")
	err := q.Add(env, []byte("body"))
	if err != nil {
		t.Fatal(err)
	}

	got, err := q.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	wantErr := errors.New("sync trash")
	trash := filepath.Join(root, dirTrash)
	seenRemoval := false
	disk.SetHooks(disk.Hooks{
		BeforeRemoveAll: func(string) error { seenRemoval = true; return nil },
		BeforeSyncDir: func(path string) error {
			if seenRemoval && filepath.Clean(path) == filepath.Clean(trash) {
				return wantErr
			}

			return nil
		},
	})

	err = q.Finish(got)
	if !errors.Is(err, ErrCleanup) || !errors.Is(err, wantErr) {
		t.Fatalf("Finish error=%v want %v", err, wantErr)
	}

	entries, err := os.ReadDir(trash)
	if err != nil || len(entries) != 0 {
		t.Fatalf("trash=%v err=%v", entries, err)
	}

	messages, bytes := q.Stats()
	if messages != 0 || bytes != 0 {
		t.Fatalf("Stats=(%d, %d) want (0, 0)", messages, bytes)
	}
}

func TestFinishAccountsRemovalBeforeTrashCleanupError(t *testing.T) {
	clearHooks(t)
	root := t.TempDir()
	q := mustOpen(t, root, Limits{})
	env := testEnv("finish-cleanup-error")
	err := q.Add(env, []byte("body"))
	if err != nil {
		t.Fatal(err)
	}

	got, err := q.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	wantErr := errors.New("remove trash")
	disk.SetHooks(disk.Hooks{BeforeRemoveAll: func(path string) error { return wantErr }})

	err = q.Finish(got)
	if !errors.Is(err, ErrCleanup) || !errors.Is(err, wantErr) {
		t.Fatalf("Finish error=%v want %v", err, wantErr)
	}

	if q.Len() != 0 {
		t.Fatalf("Len=%d want 0", q.Len())
	}

	messages, bytes := q.Stats()
	if messages != 0 || bytes != 0 {
		t.Fatalf("Stats=(%d, %d) want (0, 0)", messages, bytes)
	}

	disk.SetHooks(disk.Hooks{})
	q2 := mustReopen(t, q, root, Limits{})
	if q2.Len() != 0 {
		t.Fatalf("reopened Len=%d want 0", q2.Len())
	}
}

func TestOpenDurablyCreatesFreshTopology(t *testing.T) {
	clearHooks(t)
	base := t.TempDir()
	root := filepath.Join(base, "one", "two", "spool")
	var synced []string
	disk.SetHooks(disk.Hooks{AfterSyncDir: func(path string) error {
		synced = append(synced, filepath.Clean(path))
		return nil
	}})
	q, err := Open(root, Limits{})
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = q.Close() })

	for _, expected := range []string{base, filepath.Join(base, "one"), filepath.Join(base, "one", "two"), root} {

		count := 0

		for _, path := range synced {
			if filepath.Clean(expected) == path {
				count++
			}
		}

		if count == 0 {
			t.Fatalf("parent %s was not synced; calls=%v", expected, synced)
		}
	}

	rootSyncs := 0

	for _, path := range synced {
		if path == filepath.Clean(root) {
			rootSyncs++
		}
	}

	if rootSyncs < 6 { // each of the six state directories
		t.Fatalf("root sync count=%d want at least 6; calls=%v", rootSyncs, synced)
	}

	for _, name := range []string{dirReady, dirDead, dirTmp, dirDSN, dirCorrupt, dirTrash} {

		info, err := os.Stat(filepath.Join(root, name))
		if err != nil || !info.IsDir() {
			t.Fatalf("topology %s: info=%v err=%v", name, info, err)
		}
	}
}

func TestCloseWakesNextAndRejectsOldHandleAfterReopen(t *testing.T) {
	clearHooks(t)
	root := t.TempDir()
	q := mustOpen(t, root, Limits{})
	nextResult := make(chan error, 1)
	go func() {
		_, err := q.Next(context.Background())
		nextResult <- err
	}()
	time.Sleep(20 * time.Millisecond)

	err := q.Close()
	if err != nil {
		t.Fatal(err)
	}

	err = <-nextResult
	if !errors.Is(err, ErrQueueClosed) {
		t.Fatalf("Next error=%v want ErrQueueClosed", err)
	}

	reopened := mustOpen(t, root, Limits{})
	err = reopened.Add(testEnv("new-handle"), []byte("body"))
	if err != nil {
		t.Fatal(err)
	}

	err = q.Add(testEnv("old-handle"), []byte("body"))
	if !errors.Is(err, ErrQueueClosed) {
		t.Fatalf("old Add error=%v want ErrQueueClosed", err)
	}

	_, err = q.DeadIDs()
	if !errors.Is(err, ErrQueueClosed) {
		t.Fatalf("old DeadIDs error=%v want ErrQueueClosed", err)
	}

	if q.Len() != 0 {
		t.Fatalf("closed Len=%d want 0", q.Len())
	}
}

func TestCloseBroadcastsToBlockedNextCalls(t *testing.T) {
	clearHooks(t)
	q := mustOpen(t, t.TempDir(), Limits{})
	const consumers = 4
	nextResults := make(chan error, consumers)

	for i := 0; i < consumers; i++ {
		go func() {
			_, err := q.Next(context.Background())
			nextResults <- err
		}()
	}

	waitForActiveOperations(t, q, consumers)

	closeResult := make(chan error, 1)
	go func() { closeResult <- q.Close() }()

	select {
	case err := <-closeResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close blocked with multiple Next calls")
	}

	for i := 0; i < consumers; i++ {
		err := <-nextResults
		if !errors.Is(err, ErrQueueClosed) {
			t.Fatalf("Next[%d] error=%v want ErrQueueClosed", i, err)
		}
	}
}

func TestConcurrentCloseAndBlockedNextStress(t *testing.T) {
	const (
		iterations = 100
		consumers  = 8
		closers    = 8
	)

	for iteration := 0; iteration < iterations; iteration++ {
		q, err := OpenReadOnly(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}

		nextResults := make(chan error, consumers)

		for i := 0; i < consumers; i++ {
			go func() {
				_, err := q.Next(context.Background())
				nextResults <- err
			}()
		}

		waitForActiveOperations(t, q, consumers)

		closeResults := make(chan error, closers)

		for i := 0; i < closers; i++ {
			go func() { closeResults <- q.Close() }()
		}

		for i := 0; i < closers; i++ {
			err = <-closeResults
			if err != nil {
				t.Fatalf("iteration %d Close[%d]: %v", iteration, i, err)
			}
		}

		for i := 0; i < consumers; i++ {
			err = <-nextResults
			if !errors.Is(err, ErrQueueClosed) {
				t.Fatalf("iteration %d Next[%d] error=%v want ErrQueueClosed", iteration, i, err)
			}
		}
	}
}

func waitForActiveOperations(t *testing.T, q *Queue, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)

	for {
		q.mu.Lock()
		active := q.active
		q.mu.Unlock()

		if active == want {
			return
		}

		if time.Now().After(deadline) {
			t.Fatalf("active operations=%d want %d", active, want)
		}

		time.Sleep(time.Millisecond)
	}
}

func TestCloseWaitsForActiveDiskOperationAndIsConcurrentSafe(t *testing.T) {
	clearHooks(t)
	root := t.TempDir()
	q := mustOpen(t, root, Limits{})
	env := testEnv("close-active")
	err := q.Add(env, []byte("body"))
	if err != nil {
		t.Fatal(err)
	}

	got, err := q.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	got.NextAttempt = time.Now().Add(time.Minute)
	entered := make(chan struct{})
	release := make(chan struct{})
	disk.SetHooks(disk.Hooks{BeforeRename: func(_, newpath string) error {
		if filepath.Clean(newpath) == filepath.Join(root, dirReady, got.ID, metaName) {
			close(entered)
			<-release
		}

		return nil
	}})
	retryResult := make(chan error, 1)
	go func() { retryResult <- q.Retry(got) }()
	<-entered

	const closers = 16
	closeResults := make(chan error, closers)

	for i := 0; i < closers; i++ {
		go func() { closeResults <- q.Close() }()
	}

	time.Sleep(20 * time.Millisecond)

	_, err = Open(root, Limits{})
	if !errors.Is(err, disk.ErrLocked) {
		t.Fatalf("Open while Close waits error=%v want ErrLocked", err)
	}

	close(release)

	err = <-retryResult
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < closers; i++ {
		err = <-closeResults
		if err != nil {
			t.Fatalf("Close[%d]: %v", i, err)
		}
	}

	disk.SetHooks(disk.Hooks{})
	reopened := mustOpen(t, root, Limits{})
	if reopened.Len() != 1 {
		t.Fatalf("reopened Len=%d want 1", reopened.Len())
	}
}

func TestCloseWaitsForReaderHandle(t *testing.T) {
	clearHooks(t)
	q := mustOpen(t, t.TempDir(), Limits{})
	err := q.Add(testEnv("close-reader"), []byte("body"))
	if err != nil {
		t.Fatal(err)
	}

	reader, err := q.Reader("close-reader")
	if err != nil {
		t.Fatal(err)
	}

	closed := make(chan error, 1)
	go func() { closed <- q.Close() }()

	select {
	case err := <-closed:
		t.Fatalf("Close returned while reader was open: %v", err)
	case <-time.After(20 * time.Millisecond):
	}

	err = reader.Close()
	if err != nil {
		t.Fatal(err)
	}

	err = reader.Close()
	if err != nil {
		t.Fatalf("idempotent reader Close: %v", err)
	}

	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not finish after reader Close")
	}
}

func TestReaderErrorsReleaseOperation(t *testing.T) {
	clearHooks(t)
	q := mustOpen(t, t.TempDir(), Limits{})

	for _, id := range []string{"../bad", "missing"} {

		_, err := q.Reader(id)
		if err == nil {
			t.Fatalf("Reader(%q) succeeded", id)
		}

		q.mu.Lock()
		active := q.active
		q.mu.Unlock()

		if active != 0 {
			t.Fatalf("Reader(%q) left active=%d", id, active)
		}
	}
}

func TestReadBodyRejectsConcurrentGrowth(t *testing.T) {
	clearHooks(t)
	root := t.TempDir()
	q := mustOpen(t, root, Limits{})
	env := testEnv("growing-body")
	err := q.Add(env, []byte("body"))
	if err != nil {
		t.Fatal(err)
	}

	q.afterBodyOpen = func() {
		q.afterBodyOpen = nil
		f, err := os.OpenFile(filepath.Join(root, dirReady, env.ID, bodyName), os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}

		_, err = f.WriteString("x")
		if err != nil {
			t.Fatal(err)
		}

		err = f.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
	_, err = q.ReadBody(env.ID)
	if err == nil || !strings.Contains(err.Error(), "body size mismatch") {
		t.Fatalf("ReadBody error=%v want body size mismatch", err)
	}
}

func TestSchedulingOwnsEnvelopeCopies(t *testing.T) {
	clearHooks(t)
	q := mustOpen(t, t.TempDir(), Limits{})
	now := time.Now()
	first := testEnv("owned-first")
	first.NextAttempt = now
	second := testEnv("owned-second")
	second.NextAttempt = now.Add(time.Hour)
	err := q.Add(first, []byte("one"))
	if err != nil {
		t.Fatal(err)
	}

	err = q.Add(second, []byte("two"))
	if err != nil {
		t.Fatal(err)
	}

	first.NextAttempt = now.Add(2 * time.Hour)
	first.Recipients[0].Address = "mutated@example.net"
	first.Recipients[0].Detail = "mutated"

	got, err := q.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if got.ID != "owned-first" || got.Recipients[0].Address != "bob@example.com" || got.Recipients[0].Detail != "" {
		t.Fatalf("scheduled envelope retained caller memory: %#v", got)
	}

	q.Requeue(got)
	got.Recipients[0].Address = "changed-after-requeue@example.net"
	requeued, err := q.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if requeued.Recipients[0].Address != "bob@example.com" {
		t.Fatalf("requeue retained caller recipients: %#v", requeued.Recipients)
	}
}

func TestSchedulingCallerMutationRace(t *testing.T) {
	clearHooks(t)
	q := mustOpen(t, t.TempDir(), Limits{})
	env := testEnv("owned-race")
	err := q.Add(env, []byte("body"))
	if err != nil {
		t.Fatal(err)
	}

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)

		for {
			select {
			case <-stop:
				return
			default:
				env.Recipients[0].Detail = "caller mutation"
				env.NextAttempt = time.Now().Add(time.Hour)
			}
		}
	}()
	got, err := q.Next(context.Background())
	close(stop)
	<-done

	if err != nil {
		t.Fatal(err)
	}

	if got.Recipients[0].Detail != "" {
		t.Fatalf("scheduled detail=%q want independent copy", got.Recipients[0].Detail)
	}
}

func TestEnvelopeAndMetadataBounds(t *testing.T) {
	clearHooks(t)
	q := mustOpen(t, t.TempDir(), Limits{})

	for _, tc := range []envelopeBoundsCase{
		{name: "recipients", env: func() *Envelope {
			e := testEnv("too-many-recipients")
			e.Recipients = make([]Recipient, maxEnvelopeRecipients+1)

			for i := range e.Recipients {
				e.Recipients[i] = Recipient{Address: "bob@example.com", Status: StatusPending}
			}

			return e
		}()},
		{name: "attempts", env: func() *Envelope { e := testEnv("max-attempts"); e.Attempts = math.MaxInt; return e }()},
		{name: "control", env: func() *Envelope { e := testEnv("control-address"); e.Sender = "a\x01@example.com"; return e }()},
		{name: "delete", env: func() *Envelope {
			e := testEnv("delete-address")
			e.Recipients[0].Address = "b\x7f@example.com"
			return e
		}()},
		{name: "detail", env: func() *Envelope {
			e := testEnv("long-detail")
			e.Recipients[0].Detail = strings.Repeat("x", maxEnvelopeDetailBytes+1)
			return e
		}()},
		{name: "metadata", env: func() *Envelope {
			e := testEnv("large-metadata")
			detail := strings.Repeat("x", maxEnvelopeDetailBytes)
			e.Recipients = make([]Recipient, 65)

			for i := range e.Recipients {
				e.Recipients[i] = Recipient{Address: "bob@example.com", Status: StatusPending, Detail: detail}
			}

			return e
		}()},
	} {

		t.Run(tc.name, func(t *testing.T) {
			err := q.Add(tc.env, []byte("body"))
			if err == nil {
				t.Fatal("Add accepted invalid envelope")
			}
		})
	}

	maxRevision := testEnv("max-revision")
	maxRevision.Revision = math.MaxUint64
	err := validateEnvelope(maxRevision)
	if err == nil {
		t.Fatal("maximum revision passed validation")
	}

	root := t.TempDir()
	_ = mustOpen(t, root, Limits{}).Close()

	for _, tc := range []queueEntrySizeCase{
		{id: "oversized-meta", name: metaName, size: maxEnvelopeMetadata + 1},
		{id: "oversized-state", name: addStateName, size: maxAddStateBytes + 1},
	} {

		dir := filepath.Join(root, dirReady, tc.id)
		err := os.Mkdir(dir, 0700)
		if err != nil {
			t.Fatal(err)
		}

		err = os.WriteFile(filepath.Join(dir, bodyName), nil, 0600)
		if err != nil {
			t.Fatal(err)
		}

		err = os.WriteFile(filepath.Join(dir, tc.name), []byte(strings.Repeat("x", tc.size)), 0600)
		if err != nil {
			t.Fatal(err)
		}

		if tc.name != addStateName {
			writeAcceptedMarker(t, dir)
		}
	}

	reopened := mustOpen(t, root, Limits{})
	if reopened.Len() != 0 || len(reopened.Corrupt) != 2 {
		t.Fatalf("Len=%d Corrupt=%v want two quarantines", reopened.Len(), reopened.Corrupt)
	}
}

func TestRevisionBoundaryMutationSafety(t *testing.T) {
	clearHooks(t)
	root := t.TempDir()
	_ = mustOpen(t, root, Limits{}).Close()

	canIncrement := testEnv("revision-boundary-two")
	canIncrement.Revision = maxEnvelopeRevision - 1
	canIncrement.Size = 4
	canIncrement.NextAttempt = time.Now().Add(-2 * time.Minute)
	writeQueueEntry(t, root, dirReady, canIncrement, []byte("body"))
	blocked := testEnv("revision-boundary-one")
	blocked.Revision = maxEnvelopeRevision
	blocked.Size = 4
	blocked.NextAttempt = time.Now().Add(-time.Minute)
	writeQueueEntry(t, root, dirReady, blocked, []byte("body"))

	q := mustOpen(t, root, Limits{})

	for i := 0; i < 2; i++ {
		env, err := q.Next(context.Background())
		if err != nil {
			t.Fatal(err)
		}

		if env.ID == canIncrement.ID {
			env.NextAttempt = time.Now().Add(time.Hour)
			err = q.Retry(env)
			if err != nil {
				t.Fatalf("boundary-2 Retry: %v", err)
			}

			continue
		}

		err = q.Retry(env)
		if err == nil || !strings.Contains(err.Error(), "cannot be incremented") {
			t.Fatalf("boundary-1 Retry error=%v", err)
		}
	}

	if q.Len() != 2 {
		t.Fatalf("Len=%d want both ready items schedulable", q.Len())
	}

	stored, err := q.loadDir(filepath.Join(root, dirReady, canIncrement.ID), canIncrement.ID)
	if err != nil || stored.Revision != maxEnvelopeRevision {
		t.Fatalf("stored revision=%v err=%v", stored, err)
	}
}

func TestReviveDeadRejectsRevisionBoundaryBeforeWrite(t *testing.T) {
	clearHooks(t)
	root := t.TempDir()
	q := mustOpen(t, root, Limits{})
	env := testEnv("revive-revision-boundary")
	env.Revision = maxEnvelopeRevision
	env.Size = 4
	dir := writeQueueEntry(t, root, dirDead, env, []byte("body"))
	before, err := os.ReadFile(filepath.Join(dir, metaName))
	if err != nil {
		t.Fatal(err)
	}

	_, err = q.ReviveDead(env.ID)
	if err == nil || !strings.Contains(err.Error(), "cannot be incremented") {
		t.Fatalf("ReviveDead error=%v", err)
	}

	after, err := os.ReadFile(filepath.Join(dir, metaName))
	if err != nil || !bytes.Equal(after, before) {
		t.Fatalf("dead metadata changed: %v", err)
	}

	_, err = os.Stat(filepath.Join(dir, reviveMetaName))
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("staged metadata exists: %v", err)
	}
}

func TestAttemptsHardBoundRejectsNearMachineMaximum(t *testing.T) {
	for _, attempts := range []int{math.MaxInt - 1, math.MaxInt - 2} {

		env := testEnv(fmt.Sprintf("attempts-%d", attempts))
		env.Attempts = attempts
		err := validateEnvelope(env)
		if err == nil {
			t.Fatalf("Attempts=%d passed validation", attempts)
		}
	}
}

func TestReservationCheckedArithmeticAndFreeDiskDefault(t *testing.T) {
	clearHooks(t)
	q := mustOpen(t, t.TempDir(), Limits{MinFreeDisk: 1})
	if q.FreeDisk == nil {
		t.Fatal("Open did not initialize FreeDisk")
	}

	err := q.Reserve(-1)
	if err == nil {
		t.Fatal("negative Reserve succeeded")
	}

	q.FreeDisk = func(string) (int64, error) { return math.MaxInt64, nil }
	q.limits.MinFreeDisk = math.MaxInt64
	err = q.Reserve(1)
	if !errors.Is(err, ErrInsufficientDisk) {
		t.Fatalf("overflowing MinFreeDisk Reserve error=%v", err)
	}

	q.limits.MinFreeDisk = 0
	q.mu.Lock()
	q.bytes = math.MaxInt64
	q.mu.Unlock()

	err = q.Reserve(1)
	if !errors.Is(err, ErrQueueFull) {
		t.Fatalf("overflowing byte Reserve error=%v", err)
	}

	q.mu.Lock()
	q.bytes = 0
	q.count = math.MaxInt
	q.mu.Unlock()

	err = q.Reserve(0)
	if !errors.Is(err, ErrQueueFull) {
		t.Fatalf("overflowing count Reserve error=%v", err)
	}
}

func TestPhysicalSpoolCountsEveryNamespace(t *testing.T) {
	clearHooks(t)
	q := mustOpen(t, t.TempDir(), Limits{})
	before := q.SpoolStats().Used

	for _, dir := range []string{q.ready, q.tmp, q.dsn, q.dead, q.corr, q.trash} {

		err := os.WriteFile(filepath.Join(dir, "usage"), []byte("x"), 0600)
		if err != nil {
			t.Fatal(err)
		}
	}

	err := q.refreshSpoolUsage()
	if err != nil {
		t.Fatal(err)
	}

	after := q.SpoolStats().Used
	if after-before < 6*disk.AllocationSize(1) {
		t.Fatalf("physical usage increase=%d want at least %d", after-before, 6*disk.AllocationSize(1))
	}
}

func TestDeadCyclingDoesNotReleasePhysicalQuota(t *testing.T) {
	clearHooks(t)
	q := mustOpen(t, t.TempDir(), Limits{})
	body := []byte("body")
	first := testEnv("dead-cycle-one")
	err := q.Add(first, body)
	if err != nil {
		t.Fatal(err)
	}

	used := q.SpoolStats().Used
	q.limits.MaxSpoolBytes = used + 3*disk.AllocationSize(0) + terminalSpoolReserve
	q.limits.SpoolEmergencyBytes = 3*disk.AllocationSize(0) + terminalSpoolReserve
	err = q.Bury(first)
	if err != nil {
		t.Fatal(err)
	}

	err = q.Add(testEnv("dead-cycle-two"), body)
	if !errors.Is(err, ErrSpoolFull) {
		t.Fatalf("Add after Bury error=%v want ErrSpoolFull", err)
	}

	err = q.DeleteDead(first.ID)
	if err != nil {
		t.Fatal(err)
	}

	q.limits.MaxSpoolBytes = q.SpoolStats().Used + estimateEntryAllocation(int64(len(body)), maxEnvelopeMetadata) + q.limits.SpoolEmergencyBytes
	err = q.Add(testEnv("dead-cycle-two"), body)
	if err != nil {
		t.Fatalf("Add after DeleteDead: %v", err)
	}
}

func TestDSNCanUseEmergencySpoolReserve(t *testing.T) {
	clearHooks(t)
	q := mustOpen(t, t.TempDir(), Limits{})
	source := testEnv("emergency-dsn-source")
	err := q.Add(source, []byte("source"))
	if err != nil {
		t.Fatal(err)
	}

	dsn := testDSN(source)
	meta, err := marshalEnvelope(dsn)
	if err != nil {
		t.Fatal(err)
	}

	need := estimateEntryAllocation(3, len(meta)) + disk.AllocationSize(maxEnvelopeMetadata) + disk.AllocationSize(0)
	used := q.SpoolStats().Used
	q.limits.MaxSpoolBytes = used + need + terminalSpoolReserve
	q.limits.SpoolEmergencyBytes = need + terminalSpoolReserve
	err = q.Add(testEnv("ordinary-blocked"), []byte("dsn"))
	if !errors.Is(err, ErrSpoolFull) {
		t.Fatalf("ordinary Add error=%v want ErrSpoolFull", err)
	}

	err = q.AddDSN(source, dsn, []byte("dsn"))
	if err != nil {
		t.Fatalf("AddDSN using emergency reserve: %v", err)
	}

	err = q.Finish(source)
	if err != nil {
		t.Fatalf("Finish source after emergency DSN: %v", err)
	}
}

func TestOrdinaryReservationPreservesEmergencyFreeSpace(t *testing.T) {
	clearHooks(t)
	q := mustOpen(t, t.TempDir(), Limits{
		MinFreeDisk:         100,
		SpoolEmergencyBytes: 50,
	})
	q.FreeDisk = func(string) (int64, error) { return 149, nil }
	err := q.Reserve(0)
	if !errors.Is(err, ErrInsufficientDisk) {
		t.Fatalf("ordinary Reserve error=%v want ErrInsufficientDisk", err)
	}

	q.mu.Lock()
	err = q.reservePhysicalLocked(49, true)
	q.mu.Unlock()

	if err != nil {
		t.Fatalf("emergency reservation: %v", err)
	}

	q.mu.Lock()

	if q.reserved != 0 {
		t.Fatalf("physical-only reservation consumed %d logical slots", q.reserved)
	}

	q.spoolReserved = 0
	q.mu.Unlock()
}

func TestPhysicalReservationsAreConcurrentSafe(t *testing.T) {
	clearHooks(t)
	q := mustOpen(t, t.TempDir(), Limits{})
	q.limits.MaxSpoolBytes = q.SpoolStats().Used + 100
	errs := make(chan error, 2)
	start := make(chan struct{})

	for range 2 {
		go func() {
			<-start
			errs <- q.Reserve(60)
		}()
	}

	close(start)
	var successes, full int

	for range 2 {
		err := <-errs
		if err == nil {
			successes++
		} else if errors.Is(err, ErrSpoolFull) {
			full++
		} else {
			t.Fatal(err)
		}
	}

	if successes != 1 || full != 1 {
		t.Fatalf("successes=%d full=%d", successes, full)
	}

	q.ReleaseReserve(60)
}

func TestAddReservesMetadataAndFilesystemOverhead(t *testing.T) {
	clearHooks(t)
	q := mustOpen(t, t.TempDir(), Limits{})
	q.limits.MaxSpoolBytes = q.SpoolStats().Used + disk.AllocationSize(1)
	err := q.Add(testEnv("metadata-overhead"), []byte("x"))
	if !errors.Is(err, ErrSpoolFull) {
		t.Fatalf("Add error=%v want ErrSpoolFull", err)
	}
}

func TestAcceptedAddStaysWithinPhysicalLimit(t *testing.T) {
	clearHooks(t)
	q := mustOpen(t, t.TempDir(), Limits{})
	env := testEnv("physical-hard-limit")
	data := []byte("body")
	env.Size = int64(len(data))
	env.Incarnation = strings.Repeat("a", 32)
	env.Revision = 1
	meta, err := marshalEnvelope(env)
	if err != nil {
		t.Fatal(err)
	}

	q.limits.MaxSpoolBytes = q.SpoolStats().Used + estimateEntryAllocation(int64(len(data)), len(meta))
	added := testEnv(env.ID)
	err = q.Add(added, data)
	if err != nil {
		t.Fatal(err)
	}

	stats := q.SpoolStats()
	if stats.Used > stats.Limit {
		t.Fatalf("physical usage exceeded hard limit: used=%d limit=%d", stats.Used, stats.Limit)
	}

	q.limits.SpoolEmergencyBytes = 0
	q.limits.MaxSpoolBytes = stats.Used
	err = q.Finish(added)
	if err != nil {
		t.Fatalf("Finish at hard physical limit: %v", err)
	}
}

func TestPruneAndExplicitDelete(t *testing.T) {
	clearHooks(t)
	q := mustOpen(t, t.TempDir(), Limits{DeadRetention: time.Hour, CorruptRetention: time.Hour})
	dead := testEnv("retained-dead")
	err := q.Add(dead, []byte("body"))
	if err != nil {
		t.Fatal(err)
	}

	err = q.Bury(dead)
	if err != nil {
		t.Fatal(err)
	}

	old := time.Now().Add(-2 * time.Hour)
	err = os.Chtimes(filepath.Join(q.dead, dead.ID), old, old)
	if err != nil {
		t.Fatal(err)
	}

	corrupt := filepath.Join(q.corr, "old-corrupt")
	err = os.WriteFile(corrupt, []byte("bad"), 0600)
	if err != nil {
		t.Fatal(err)
	}

	err = os.Chtimes(corrupt, old, old)
	if err != nil {
		t.Fatal(err)
	}

	deadCount, corruptCount, err := q.Prune(time.Now())
	if err != nil || deadCount != 1 || corruptCount != 1 {
		t.Fatalf("Prune dead=%d corrupt=%d err=%v", deadCount, corruptCount, err)
	}

	second := testEnv("explicit-dead")
	err = q.Add(second, []byte("body"))
	if err != nil {
		t.Fatal(err)
	}

	err = q.Bury(second)
	if err != nil {
		t.Fatal(err)
	}

	err = q.DeleteDead(second.ID)
	if err != nil {
		t.Fatal(err)
	}

	_, err = os.Stat(filepath.Join(q.dead, second.ID))
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("dead entry remains: %v", err)
	}
}

func TestFailedQuarantineBlocksBadEntryAndLoadsValidEntry(t *testing.T) {
	clearHooks(t)
	root := t.TempDir()

	for _, dir := range []string{dirReady, dirDead, dirTmp, dirDSN, dirCorrupt, dirTrash} {

		err := os.MkdirAll(filepath.Join(root, dir), 0700)
		if err != nil {
			t.Fatal(err)
		}
	}

	valid := testEnv("valid-beside-bad")
	valid.Size = 4
	writeQueueEntry(t, root, dirReady, valid, []byte("body"))
	bad := filepath.Join(root, dirReady, "bad-entry")
	err := os.MkdirAll(bad, 0700)
	if err != nil {
		t.Fatal(err)
	}

	disk.SetHooks(disk.Hooks{BeforeRename: func(oldpath, _ string) error {
		if filepath.Clean(oldpath) == filepath.Clean(bad) {
			return errors.New("quarantine unavailable")
		}

		return nil
	}})
	q, err := Open(root, Limits{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	t.Cleanup(func() { _ = q.Close() })

	if q.Len() != 1 {
		t.Fatalf("loaded=%d want 1", q.Len())
	}

	if len(q.Corrupt) == 0 || !strings.Contains(q.Corrupt[0].Error(), "QUARANTINE FAILED; BLOCKED") {
		t.Fatalf("missing prominent quarantine issue: %v", q.Corrupt)
	}

	err = q.Add(testEnv("bad-entry"), []byte("replacement"))
	if !errors.Is(err, ErrIDConflict) {
		t.Fatalf("Add over blocked entry error=%v want ErrIDConflict", err)
	}

	_, err = os.Stat(bad)
	if err != nil {
		t.Fatalf("blocked evidence was removed: %v", err)
	}
}

func TestFailedInvalidDeadQuarantineDoesNotAbortRecovery(t *testing.T) {
	clearHooks(t)
	root := t.TempDir()

	for _, dir := range []string{dirReady, dirDead, dirTmp, dirDSN, dirCorrupt, dirTrash} {

		err := os.MkdirAll(filepath.Join(root, dir), 0700)
		if err != nil {
			t.Fatal(err)
		}
	}

	blocked := testEnv("blocked-dead-collision")
	blocked.Size = 4
	writeQueueEntry(t, root, dirReady, blocked, []byte("body"))
	deadDir := filepath.Join(root, dirDead, blocked.ID)
	err := os.MkdirAll(deadDir, 0700)
	if err != nil {
		t.Fatal(err)
	}

	valid := testEnv("valid-beside-dead")
	valid.Size = 4
	writeQueueEntry(t, root, dirReady, valid, []byte("body"))
	disk.SetHooks(disk.Hooks{BeforeRename: func(oldpath, _ string) error {
		if filepath.Clean(oldpath) == filepath.Clean(deadDir) {
			return errors.New("dead quarantine unavailable")
		}

		return nil
	}})

	q, err := Open(root, Limits{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	t.Cleanup(func() { _ = q.Close() })

	if q.Len() != 1 {
		t.Fatalf("Len=%d want only unrelated valid entry", q.Len())
	}

	err = q.Add(testEnv(blocked.ID), []byte("replacement"))
	if !errors.Is(err, ErrIDConflict) {
		t.Fatalf("Add over blocked collision error=%v want ErrIDConflict", err)
	}

	if len(q.Corrupt) == 0 || !strings.Contains(q.Corrupt[len(q.Corrupt)-1].Error(), "QUARANTINE FAILED; BLOCKED") {
		t.Fatalf("missing blocked collision report: %v", q.Corrupt)
	}
}

const queueCrashExitCode = 86

func TestQueueCrashHelper(t *testing.T) {
	scenario := os.Getenv("OUTBOXD_QUEUE_CRASH_SCENARIO")
	if scenario == "" {
		return
	}

	root := os.Getenv("OUTBOXD_QUEUE_CRASH_ROOT")
	q, err := Open(root, Limits{})
	if err != nil {
		os.Exit(87)
	}

	crash := func() error { os.Exit(queueCrashExitCode); return nil }

	switch scenario {
	case "add-after-rename":
		disk.SetHooks(disk.Hooks{AfterRename: func(oldpath, newpath string) error {
			if filepath.Clean(oldpath) == filepath.Join(root, dirTmp, "crash-add") && filepath.Clean(newpath) == filepath.Join(root, dirReady, "crash-add") {
				return crash()
			}

			return nil
		}})
		_ = q.Add(testEnv("crash-add"), []byte("body"))
	case "add-after-accept-sync":
		state := filepath.Join(root, dirReady, "crash-accepted", addStateName)
		disk.SetHooks(disk.Hooks{AfterSyncFile: func(path string) error {
			if filepath.Clean(path) == filepath.Clean(state) {
				return crash()
			}

			return nil
		}})
		_ = q.Add(testEnv("crash-accepted"), []byte("body"))
	case "retry-after-meta-rename":
		env, nextErr := q.Next(context.Background())
		if nextErr != nil {
			os.Exit(87)
		}

		env.NextAttempt = env.NextAttempt.Add(time.Hour)
		meta := filepath.Join(root, dirReady, env.ID, metaName)
		disk.SetHooks(disk.Hooks{AfterRename: func(_, newpath string) error {
			if filepath.Clean(newpath) == filepath.Clean(meta) {
				return crash()
			}

			return nil
		}})
		_ = q.Retry(env)
	case "finish-before-source-sync", "finish-after-source-sync":
		env, nextErr := q.Next(context.Background())
		if nextErr != nil {
			os.Exit(87)
		}

		disk.SetHooks(disk.Hooks{
			BeforeSyncDir: func(path string) error {
				if scenario == "finish-before-source-sync" && filepath.Clean(path) == filepath.Join(root, dirReady) {
					return crash()
				}

				return nil
			},
			AfterSyncDir: func(path string) error {
				if scenario == "finish-after-source-sync" && filepath.Clean(path) == filepath.Join(root, dirReady) {
					return crash()
				}

				return nil
			},
		})
		_ = q.Finish(env)
	default:
		os.Exit(87)
	}

	os.Exit(88)
}

func runQueueCrash(t *testing.T, root, scenario string) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestQueueCrashHelper$")
	cmd.Env = append(os.Environ(), "OUTBOXD_QUEUE_CRASH_ROOT="+root, "OUTBOXD_QUEUE_CRASH_SCENARIO="+scenario)
	err = cmd.Run()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatalf("crash helper %s timed out", scenario)
	}

	var exitErr *exec.ExitError

	if !errors.As(err, &exitErr) || exitErr.ExitCode() != queueCrashExitCode {
		t.Fatalf("crash helper %s error=%v", scenario, err)
	}
}

func TestQueueSubprocessCrashRecovery(t *testing.T) {
	for _, scenario := range []string{"add-after-rename", "add-after-accept-sync", "retry-after-meta-rename", "finish-before-source-sync", "finish-after-source-sync"} {

		t.Run(scenario, func(t *testing.T) {
			clearHooks(t)
			root := t.TempDir()
			q := mustOpen(t, root, Limits{})
			if strings.HasPrefix(scenario, "retry-") {
				err := q.Add(testEnv("crash-retry"), []byte("body"))
				if err != nil {
					t.Fatal(err)
				}
			}

			if strings.HasPrefix(scenario, "finish-") {
				err := q.Add(testEnv("crash-finish"), []byte("body"))
				if err != nil {
					t.Fatal(err)
				}
			}

			err := q.Close()
			if err != nil {
				t.Fatal(err)
			}

			runQueueCrash(t, root, scenario)

			reopened := mustOpen(t, root, Limits{})

			switch scenario {
			case "add-after-rename":
				if reopened.Len() != 0 || len(reopened.Corrupt) == 0 {
					t.Fatalf("Len=%d Corrupt=%v", reopened.Len(), reopened.Corrupt)
				}
			case "add-after-accept-sync":
				if reopened.Len() != 1 {
					t.Fatalf("Len=%d want 1", reopened.Len())
				}
			case "retry-after-meta-rename":
				if reopened.Len() != 1 {
					t.Fatalf("Len=%d want 1", reopened.Len())
				}

				env, err := reopened.loadDir(filepath.Join(root, dirReady, "crash-retry"), "crash-retry")
				if err != nil || env.Revision != 2 || !env.NextAttempt.After(time.Now().Add(30*time.Minute)) {
					t.Fatalf("stored envelope=%#v err=%v", env, err)
				}
			default:
				if reopened.Len() != 0 {
					t.Fatalf("finished message recovered, Len=%d", reopened.Len())
				}

				entries, err := os.ReadDir(filepath.Join(root, dirTrash))
				if err != nil || len(entries) != 0 {
					t.Fatalf("trash=%v err=%v", entries, err)
				}
			}
		})
	}
}
