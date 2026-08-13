//go:build !windows

package queue

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadOnlyRejectsSymlinkEntry(t *testing.T) {
	root := t.TempDir()

	q := mustOpen(t, root, Limits{})

	env := testEnv("safe-entry")

	err := q.Add(env, []byte("safe"))
	if err != nil {
		t.Fatal(err)
	}

	err = q.Close()
	if err != nil {
		t.Fatal(err)
	}

	external := t.TempDir()

	writeQueueEntry(t, filepath.Dir(external), filepath.Base(external), env, []byte("external"))

	external = filepath.Join(external, env.ID)
	entry := filepath.Join(root, dirReady, env.ID)

	err = os.RemoveAll(entry)
	if err != nil {
		t.Fatal(err)
	}

	err = os.Symlink(external, entry)
	if err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	readOnly, err := OpenReadOnly(root)
	if err != nil {
		t.Fatal(err)
	}

	defer readOnly.Close()

	_, err = readOnly.LoadReady(env.ID)
	if err == nil {
		t.Fatal("symlink entry was inspected")
	}
}
