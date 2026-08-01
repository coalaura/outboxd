package disk

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
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

	err := MkdirDurable(b)
	if err != nil {
		t.Fatal(err)
	}

	want := []string{filepath.Clean(base), filepath.Clean(a)}
	if !reflect.DeepEqual(synced, want) {
		t.Fatalf("synced=%v want %v", synced, want)
	}

	err = MkdirDurable(b)
	if err != nil {
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

	_, statErr := os.Stat(filepath.Join(base, "a"))
	if !os.IsNotExist(statErr) {
		t.Fatalf("failed component was not rolled back: %v", statErr)
	}
}

func TestAllocatedBytesDoesNotFollowSymlinks(t *testing.T) {
	root := t.TempDir()
	external := filepath.Join(t.TempDir(), "external")
	err := os.Mkdir(external, 0700)
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile(filepath.Join(external, "large"), make([]byte, 1<<20), 0600)
	if err != nil {
		t.Fatal(err)
	}

	err = os.Symlink(external, filepath.Join(root, "link"))
	if err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	used, err := AllocatedBytes(root)
	if err != nil {
		t.Fatal(err)
	}

	if used >= 1<<20 {
		t.Fatalf("usage %d followed external symlink", used)
	}
}

func TestValidatePathRejectsSymlinkComponent(t *testing.T) {
	root := t.TempDir()
	external := t.TempDir()
	link := filepath.Join(root, "link")
	err := os.Symlink(external, link)
	if err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	err = ValidatePath(filepath.Join(link, "spool"))
	if err == nil || !strings.Contains(err.Error(), "symbolic link or reparse point") {
		t.Fatalf("ValidatePath error=%v", err)
	}
}

func TestAllocationSizeUsesConservativeUnit(t *testing.T) {
	got := AllocationSize(1)
	if got != 64<<10 {
		t.Fatalf("AllocationSize(1)=%d want %d", got, 64<<10)
	}

	got = AllocationSize((64 << 10) + 1)
	if got != 128<<10 {
		t.Fatalf("AllocationSize(unit+1)=%d want %d", got, 128<<10)
	}
}

func TestRenameSyncsDestinationBeforeSource(t *testing.T) {
	resetHooks(t)
	root := t.TempDir()
	srcDir := filepath.Join(root, "src")
	dstDir := filepath.Join(root, "dst")
	err := os.Mkdir(srcDir, 0700)
	if err != nil {
		t.Fatal(err)
	}

	err = os.Mkdir(dstDir, 0700)
	if err != nil {
		t.Fatal(err)
	}

	src := filepath.Join(srcDir, "entry")
	dst := filepath.Join(dstDir, "entry")
	err = os.WriteFile(src, []byte("x"), 0600)
	if err != nil {
		t.Fatal(err)
	}

	var synced []string
	SetHooks(Hooks{AfterSyncDir: func(path string) error {
		synced = append(synced, filepath.Clean(path))
		return nil
	}})

	err = Rename(src, dst)
	if err != nil {
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
	err := os.WriteFile(path, []byte("old"), 0600)
	if err != nil {
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
	err = Write(path, []byte("new complete metadata"), 0600)
	if !errors.Is(err, wantErr) {
		t.Fatalf("Write error=%v want %v", err, wantErr)
	}

	body, readErr := os.ReadFile(path)
	if readErr != nil || string(body) != "new complete metadata" {
		t.Fatalf("replacement body=%q err=%v", body, readErr)
	}
}
