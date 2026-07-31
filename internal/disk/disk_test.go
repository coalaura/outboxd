package disk

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func resetHooks(t *testing.T) {
	t.Helper()
	SetHooks(Hooks{})
	t.Cleanup(func() { SetHooks(Hooks{}) })
}

func TestMkdirDurableSyncsEveryNewParent(t *testing.T) {
	resetHooks(t)
	base := t.TempDir()
	a := filepath.Join(base, "a")
	b := filepath.Join(a, "b")
	var synced []string
	SetHooks(Hooks{AfterSyncDir: func(path string) error {
		synced = append(synced, filepath.Clean(path))
		return nil
	}})

	if err := MkdirDurable(b); err != nil {
		t.Fatal(err)
	}
	want := []string{filepath.Clean(base), filepath.Clean(a)}
	if !reflect.DeepEqual(synced, want) {
		t.Fatalf("synced=%v want %v", synced, want)
	}
	if err := MkdirDurable(b); err != nil {
		t.Fatal(err)
	}
	if len(synced) <= len(want) {
		t.Fatalf("existing directory did not re-sync ancestors: %v", synced)
	}
}

func TestMkdirDurablePropagatesParentSyncFailure(t *testing.T) {
	resetHooks(t)
	base := t.TempDir()
	wantErr := errors.New("sync parent")
	SetHooks(Hooks{BeforeSyncDir: func(path string) error {
		if filepath.Clean(path) == filepath.Clean(base) {
			return wantErr
		}
		return nil
	}})
	err := MkdirDurable(filepath.Join(base, "a", "b"))
	if !errors.Is(err, wantErr) {
		t.Fatalf("MkdirDurable error=%v want %v", err, wantErr)
	}
	if _, statErr := os.Stat(filepath.Join(base, "a")); !os.IsNotExist(statErr) {
		t.Fatalf("failed component was not rolled back: %v", statErr)
	}
}

func TestRenameSyncsDestinationBeforeSource(t *testing.T) {
	resetHooks(t)
	root := t.TempDir()
	srcDir := filepath.Join(root, "src")
	dstDir := filepath.Join(root, "dst")
	if err := os.Mkdir(srcDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dstDir, 0700); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(srcDir, "entry")
	dst := filepath.Join(dstDir, "entry")
	if err := os.WriteFile(src, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	var synced []string
	SetHooks(Hooks{AfterSyncDir: func(path string) error {
		synced = append(synced, filepath.Clean(path))
		return nil
	}})
	if err := Rename(src, dst); err != nil {
		t.Fatal(err)
	}
	want := []string{filepath.Clean(dstDir), filepath.Clean(srcDir)}
	if !reflect.DeepEqual(synced, want) {
		t.Fatalf("sync order=%v want %v", synced, want)
	}
}

func TestWriteReplacesFileAndReportsParentSyncFailure(t *testing.T) {
	resetHooks(t)
	root := t.TempDir()
	path := filepath.Join(root, "meta.json")
	if err := os.WriteFile(path, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	wantErr := errors.New("sync replacement parent")
	renamed := false
	SetHooks(Hooks{
		AfterRename: func(_, newpath string) error {
			if filepath.Clean(newpath) == filepath.Clean(path) {
				renamed = true
			}
			return nil
		},
		BeforeSyncDir: func(dir string) error {
			if renamed && filepath.Clean(dir) == filepath.Clean(root) {
				return wantErr
			}
			return nil
		},
	})
	err := Write(path, []byte("new complete metadata"), 0600)
	if !errors.Is(err, wantErr) {
		t.Fatalf("Write error=%v want %v", err, wantErr)
	}
	body, readErr := os.ReadFile(path)
	if readErr != nil || string(body) != "new complete metadata" {
		t.Fatalf("replacement body=%q err=%v", body, readErr)
	}
}
