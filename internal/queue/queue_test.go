package queue

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coalaura/outboxd/internal/disk"
)

func clearHooks(t *testing.T) {
	t.Helper()
	t.Cleanup(func() { disk.SetHooks(disk.Hooks{}) })
	disk.SetHooks(disk.Hooks{})
}

func testEnv(id string) *Envelope {
	now := time.Now().UTC().Truncate(time.Second)
	return &Envelope{
		ID:       id,
		Username: "alice",
		Sender:   "alice@example.com",
		Recipients: []Recipient{
			{Address: "bob@example.com", Domain: "example.com", Status: StatusPending},
		},
		Created:     now,
		NextAttempt: now,
	}
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
		if err := prev.Close(); err != nil {
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
	if err := os.WriteFile(filepath.Join(dir, addStateName), []byte(addAccepted), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestAddPersistsAndOpenRecovers(t *testing.T) {
	clearHooks(t)
	root := t.TempDir()
	q := mustOpen(t, root, Limits{})

	body := []byte("From: a\r\nTo: b\r\n\r\nhello\r\n")
	env := testEnv("msg001")
	if err := q.Add(env, body); err != nil {
		t.Fatal(err)
	}

	metaPath := filepath.Join(root, dirReady, "msg001", metaName)
	bodyPath := filepath.Join(root, dirReady, "msg001", bodyName)
	statePath := filepath.Join(root, dirReady, "msg001", addStateName)
	if _, err := os.Stat(metaPath); err != nil {
		t.Fatalf("meta missing: %v", err)
	}
	if _, err := os.Stat(bodyPath); err != nil {
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

	cases := []struct {
		name  string
		hooks func(id string) disk.Hooks
	}{
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
			if _, err := os.Stat(readyPath); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("uncommitted ready entry was not quarantined: %v", err)
			}
			if _, err := os.Stat(tmpPath); err == nil {
				t.Fatal("tmp dir left after Open")
			}
		})
	}
}

func TestRecoverTmpNeverPromotesCompleteUncommittedAdd(t *testing.T) {
	clearHooks(t)
	for _, state := range []struct {
		name string
		body []byte
	}{
		{name: "markerless"},
		{name: "pending", body: []byte(addPending)},
		{name: "accepted", body: []byte(addAccepted)},
	} {
		t.Run(state.name, func(t *testing.T) {
			root := t.TempDir()
			_ = mustOpen(t, root, Limits{}).Close()
			id := "tmp-" + state.name
			dir := filepath.Join(root, dirTmp, id)
			if err := os.MkdirAll(dir, 0700); err != nil {
				t.Fatal(err)
			}
			env := testEnv(id)
			message := []byte("complete body\r\n")
			env.Size = int64(len(message))
			meta, err := json.Marshal(env)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, bodyName), message, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, metaName), meta, 0600); err != nil {
				t.Fatal(err)
			}
			if state.body != nil {
				if err := os.WriteFile(filepath.Join(dir, addStateName), state.body, 0600); err != nil {
					t.Fatal(err)
				}
			}

			q := mustOpen(t, root, Limits{})
			if q.Len() != 0 {
				t.Fatalf("uncommitted tmp entry was scheduled, Len=%d", q.Len())
			}
			if _, err := os.Stat(filepath.Join(root, dirReady, id)); !errors.Is(err, os.ErrNotExist) {
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
	for _, state := range []struct {
		name string
		body []byte
	}{
		{name: "missing"},
		{name: "pending", body: []byte(addPending)},
		{name: "malformed", body: []byte("outboxd-add-v1:accept")},
	} {
		t.Run(state.name, func(t *testing.T) {
			root := t.TempDir()
			_ = mustOpen(t, root, Limits{}).Close()
			id := "ready-" + state.name
			dir := filepath.Join(root, dirReady, id)
			if err := os.MkdirAll(dir, 0700); err != nil {
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
				if err := os.WriteFile(filepath.Join(dir, name), body, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if state.body != nil {
				if err := os.WriteFile(filepath.Join(dir, addStateName), state.body, 0600); err != nil {
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
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	env := testEnv(id)
	raw, _ := json.Marshal(env)
	if err := os.WriteFile(filepath.Join(dir, metaName), raw, 0600); err != nil {
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
	if n := len(corruptEntries(t, root)); n == 0 {
		t.Fatal("expected quarantine dir entries")
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("source should be moved, err=%v", err)
	}
}

func TestBodyWithoutMetaQuarantine(t *testing.T) {
	clearHooks(t)
	root := t.TempDir()
	_ = mustOpen(t, root, Limits{}).Close()

	id := "orphanbody"
	dir := filepath.Join(root, dirReady, id)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, bodyName), []byte("x"), 0600); err != nil {
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
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, metaName), []byte("{not json"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, bodyName), []byte("x"), 0600); err != nil {
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
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	env := testEnv("otherid1")
	raw, _ := json.Marshal(env)
	if err := os.WriteFile(filepath.Join(dir, metaName), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, bodyName), []byte("x"), 0600); err != nil {
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
		if err := ValidateID(id); err == nil {
			t.Errorf("ValidateID(%q) want error", id)
		}
		env := testEnv("ok")
		env.ID = id
		if err := q.Add(env, []byte("x")); err == nil {
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
	if err := q.Add(env, []byte("x")); err == nil {
		t.Fatal("expected invalid status rejection")
	}
}

func TestRetryPersistenceFailureStillRecoverable(t *testing.T) {
	clearHooks(t)
	root := t.TempDir()
	q := mustOpen(t, root, Limits{})
	env := testEnv("retry1")
	if err := q.Add(env, []byte("body\r\n")); err != nil {
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

	if err := q.Retry(got); err == nil {
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

func TestBuryAtomic(t *testing.T) {
	clearHooks(t)
	root := t.TempDir()
	q := mustOpen(t, root, Limits{})
	env := testEnv("bury1")
	if err := q.Add(env, []byte("body\r\n")); err != nil {
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

	if err := q.Bury(got); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, dirDead, "bury1", metaName)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, dirReady, "bury1")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("still in ready")
	}

	// Partial fail: meta ok then rename fails — still recoverable.
	env2 := testEnv("bury2")
	if err := q.Add(env2, []byte("body2\r\n")); err != nil {
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
	if err := q.Bury(got2); err == nil {
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
		if _, err := os.Stat(filepath.Join(root, dirReady, "bury2")); err != nil {
			t.Fatal("bury2 not recoverable")
		}
	}
}

func TestBuryDoesNotHideReadyMarkerError(t *testing.T) {
	clearHooks(t)
	root := t.TempDir()
	q := mustOpen(t, root, Limits{})
	env := testEnv("bury-bad-marker")
	if err := q.Add(env, []byte("body")); err != nil {
		t.Fatal(err)
	}
	got, err := q.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got.Recipients[0].Status = StatusFailed
	if err := os.WriteFile(filepath.Join(root, dirReady, got.ID, addStateName), []byte("invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, dirDead, got.ID), 0700); err != nil {
		t.Fatal(err)
	}

	if err := q.Bury(got); err == nil {
		t.Fatal("Bury should report the invalid ready marker")
	}
	if q.Len() != 1 {
		t.Fatalf("Len=%d want 1", q.Len())
	}
	if messages, bytes := q.Stats(); messages != 1 || bytes != 4 {
		t.Fatalf("Stats=(%d, %d) want (1, 4)", messages, bytes)
	}
	if _, err := os.Stat(filepath.Join(root, dirReady, got.ID)); err != nil {
		t.Fatalf("ready entry removed: %v", err)
	}
}

func TestFinishCrashSafeTrash(t *testing.T) {
	clearHooks(t)
	root := t.TempDir()
	q := mustOpen(t, root, Limits{})
	env := testEnv("fin1")
	if err := q.Add(env, []byte("body\r\n")); err != nil {
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

	if trashDst != "" {
		// Simulate crash before RemoveAll by ensuring trash has content
		if _, err := os.Stat(trashDst); err != nil {
			// rename may have been rolled back on hook error — AfterRename runs after rename
			// so disk still has trash entry unless Finish cleaned partially
		}
	}
	// ready must not hold finish-committed id if rename succeeded
	if trashDst != "" {
		if _, err := os.Stat(filepath.Join(root, dirReady, "fin1")); err == nil {
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
	if err := q.Add(a, []byte("a")); err != nil {
		t.Fatal(err)
	}
	if err := q.Add(b, []byte("bbbbb")); err != nil {
		t.Fatal(err)
	}

	got, err := q.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != a.ID {
		t.Fatalf("Next ID=%s want %s", got.ID, a.ID)
	}
	if err := q.Finish(got); err != nil {
		t.Fatal(err)
	}
	if err := q.Finish(got); err != nil {
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
				if err := q.Add(env, []byte("body")); err != nil {
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
				if messages, bytes := q.Stats(); messages != 0 || bytes != 0 {
					t.Fatalf("Stats=(%d, %d) want (0, 0)", messages, bytes)
				}
				if _, err := os.Stat(filepath.Join(root, dirReady, got.ID)); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("ready entry remains: %v", err)
				}
				if operation == "bury" {
					if _, err := os.Stat(filepath.Join(root, dirDead, got.ID, bodyName)); err != nil {
						t.Fatalf("dead body: %v", err)
					}
					if err := q.Bury(got); err != nil {
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
	if err := q.Add(dead, []byte("dead")); err != nil {
		t.Fatal(err)
	}
	got, err := q.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got.Recipients[0].Status = StatusFailed
	got.Recipients[0].Detail = "permanent diagnostic"
	if err := q.Bury(got); err != nil {
		t.Fatal(err)
	}
	originalPath := filepath.Join(root, dirDead, dead.ID, metaName)
	original, err := os.ReadFile(originalPath)
	if err != nil {
		t.Fatal(err)
	}

	if err := q.Add(testEnv("capacity-holder"), []byte("live")); err != nil {
		t.Fatal(err)
	}
	if _, err := q.ReviveDead(dead.ID); !errors.Is(err, ErrQueueFull) {
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
	if err := q.Finish(holder); err != nil {
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
	if _, err := q.ReviveDead(dead.ID); err == nil {
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
	if messages, bytes := q.Stats(); messages != 0 || bytes != 0 {
		t.Fatalf("Stats=(%d, %d) want (0, 0)", messages, bytes)
	}

	revived, err := q.ReviveDead(dead.ID)
	if err != nil {
		t.Fatal(err)
	}
	if revived.Recipients[0].Status != StatusPending || revived.LastError != "" {
		t.Fatalf("unexpected revived envelope: %#v", revived)
	}
	if messages, bytes := q.Stats(); messages != 1 || bytes != 4 {
		t.Fatalf("Stats=(%d, %d) want (1, 4)", messages, bytes)
	}
	q2 := mustReopen(t, q, root, Limits{MaxMessages: 1})
	if q2.Len() != 1 {
		t.Fatalf("reopened Len=%d want 1", q2.Len())
	}
}

func TestOpenCompletesInterruptedRevive(t *testing.T) {
	clearHooks(t)
	root := t.TempDir()
	q := mustOpen(t, root, Limits{})
	env := testEnv("revive-crash")
	if err := q.Add(env, []byte("body")); err != nil {
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
	if err := q.Bury(got); err != nil {
		t.Fatal(err)
	}

	got.Recipients[0].Status = StatusPending
	got.Recipients[0].Detail = ""
	got.Attempts = 0
	got.LastError = ""
	deadDir := filepath.Join(root, dirDead, got.ID)
	if err := q.writeMeta(filepath.Join(deadDir, reviveMetaName), got); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(deadDir, filepath.Join(root, dirReady, got.ID)); err != nil {
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
	if _, err := os.Stat(filepath.Join(root, dirReady, got.ID, reviveMetaName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("staged revive metadata remains: %v", err)
	}
}

func TestSameIDTransitionHasSingleOwner(t *testing.T) {
	clearHooks(t)
	root := t.TempDir()
	q := mustOpen(t, root, Limits{})
	env := testEnv("transition-owner")
	if err := q.Add(env, []byte("body")); err != nil {
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
	if err := q.Bury(got); !errors.Is(err, ErrQueueBusy) {
		t.Fatalf("concurrent Bury want ErrQueueBusy, got %v", err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	disk.SetHooks(disk.Hooks{})
	if q.Len() != 0 {
		t.Fatalf("Len=%d want 0", q.Len())
	}
	if messages, bytes := q.Stats(); messages != 0 || bytes != 0 {
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
			if err := q.Add(testEnv(id), []byte("x")); err != nil {
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
	if err := q.Add(testEnv("q1"), []byte("a")); err != nil {
		t.Fatal(err)
	}
	if err := q.Add(testEnv("q2"), []byte("b")); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("want ErrQueueFull got %v", err)
	}

	root2 := t.TempDir()
	q2 := mustOpen(t, root2, Limits{MaxBytes: 10})
	if err := q2.Add(testEnv("b1"), []byte("12345")); err != nil {
		t.Fatal(err)
	}
	if err := q2.Add(testEnv("b2"), []byte("1234567890")); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("want ErrQueueFull got %v", err)
	}

	root3 := t.TempDir()
	q3 := mustOpen(t, root3, Limits{MinFreeDisk: 1 << 30})
	q3.FreeDisk = func(string) (int64, error) { return 100, nil }
	if err := q3.Add(testEnv("d1"), []byte("x")); !errors.Is(err, ErrInsufficientDisk) {
		t.Fatalf("want ErrInsufficientDisk got %v", err)
	}
}

func TestDSNExemptFromMessageQuota(t *testing.T) {
	clearHooks(t)
	q := mustOpen(t, t.TempDir(), Limits{MaxMessages: 1})
	if err := q.Add(testEnv("ord1"), []byte("a")); err != nil {
		t.Fatal(err)
	}
	dsn := testEnv("dsn1")
	dsn.IsDSN = true
	dsn.Sender = ""
	if err := q.Add(dsn, []byte("dsn-body")); err != nil {
		t.Fatalf("DSN Add must succeed at MaxMessages: %v", err)
	}
	if err := q.Add(testEnv("ord2"), []byte("b")); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("ordinary Add want ErrQueueFull got %v", err)
	}
}

func TestDSNStillSubjectToMinFreeDisk(t *testing.T) {
	clearHooks(t)
	q := mustOpen(t, t.TempDir(), Limits{MinFreeDisk: 1 << 30})
	q.FreeDisk = func(string) (int64, error) { return 100, nil }
	dsn := testEnv("dsn-disk")
	dsn.IsDSN = true
	dsn.Sender = ""
	if err := q.Add(dsn, []byte("x")); !errors.Is(err, ErrInsufficientDisk) {
		t.Fatalf("want ErrInsufficientDisk got %v", err)
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
	if err := q1.Close(); err != nil {
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
	if err := q.Add(env, body); err != nil {
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
	if err := q.Bury(got); err != nil {
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
	if err := ro.Add(testEnv("x"), []byte("y")); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("Add want ErrReadOnly got %v", err)
	}
	if err := ro.Reserve(1); !errors.Is(err, ErrReadOnly) {
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
		if err := os.MkdirAll(dir, 0700); err != nil {
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
		if _, err := os.Stat(filepath.Join(root, dirReady, name)); !errors.Is(err, os.ErrNotExist) {
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
	if err := q.Add(&Envelope{
		ID: "u3", Username: "u", Sender: "björn@ex.com",
		Recipients:  []Recipient{{Address: "åke@ex.com", Domain: "ex.com", Status: StatusPending}},
		Created:     now,
		NextAttempt: now,
		SMTPUTF8:    true,
	}, body); err != nil {
		t.Fatal(err)
	}

	// ASCII with SMTPUTF8 false accepted.
	if err := q.Add(&Envelope{
		ID: "uip4", Username: "u", Sender: "a@ex.com",
		Recipients:  []Recipient{{Address: "b@ex.com", Domain: "ex.com", Status: StatusPending}},
		Created:     now,
		NextAttempt: now,
		SMTPUTF8:    false,
	}, body); err != nil {
		t.Fatal(err)
	}

	// ASCII with SMTPUTF8 true accepted (headers may require it).
	if err := q.Add(&Envelope{
		ID: "u5", Username: "u", Sender: "a@ex.com",
		Recipients:  []Recipient{{Address: "b@ex.com", Domain: "ex.com", Status: StatusPending}},
		Created:     now,
		NextAttempt: now,
		SMTPUTF8:    true,
	}, body); err != nil {
		t.Fatal(err)
	}

	// Null sender DSN with ASCII recipient, no SMTPUTF8.
	if err := q.Add(&Envelope{
		ID: "u6", Username: "u", Sender: "", IsDSN: true,
		Recipients:  []Recipient{{Address: "b@ex.com", Domain: "ex.com", Status: StatusPending}},
		Created:     now,
		NextAttempt: now,
		SMTPUTF8:    false,
	}, body); err != nil {
		t.Fatal(err)
	}

	// Null sender DSN with UTF-8 recipient requires SMTPUTF8.
	err = q.Add(&Envelope{
		ID: "u7", Username: "u", Sender: "", IsDSN: true,
		Recipients:  []Recipient{{Address: "björn@ex.com", Domain: "ex.com", Status: StatusPending}},
		Created:     now,
		NextAttempt: now,
		SMTPUTF8:    false,
	}, body)
	if err == nil {
		t.Fatal("DSN UTF-8 recipient without SMTPUTF8 must reject")
	}
	if err := q.Add(&Envelope{
		ID: "u8", Username: "u", Sender: "", IsDSN: true,
		Recipients:  []Recipient{{Address: "björn@ex.com", Domain: "ex.com", Status: StatusPending}},
		Created:     now,
		NextAttempt: now,
		SMTPUTF8:    true,
	}, body); err != nil {
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
	if err := os.MkdirAll(dir, 0700); err != nil {
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
	if err := os.WriteFile(filepath.Join(dir, metaName), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, bodyName), []byte("From: x\r\n\r\n"), 0600); err != nil {
		t.Fatal(err)
	}
	writeAcceptedMarker(t, dir)
	q := mustOpen(t, root, Limits{})
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("violating ready entry must be quarantined on Open")
	}
	if len(corruptEntries(t, root)) == 0 && len(q.Corrupt) == 0 {
		t.Fatal("expected quarantine/corrupt report")
	}
	if q.Len() != 0 {
		t.Fatal("must not schedule violating entry")
	}
}
