//go:build !windows

package disk

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRemoveAllDoesNotFollowSymlink(t *testing.T) {
	root := t.TempDir()
	external := t.TempDir()

	outside := filepath.Join(external, "keep")

	err := os.WriteFile(outside, []byte("keep"), 0600)
	if err != nil {
		t.Fatal(err)
	}

	target := filepath.Join(root, "target")

	err = os.Mkdir(target, 0700)
	if err != nil {
		t.Fatal(err)
	}

	err = os.Symlink(external, filepath.Join(target, "link"))
	if err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	err = RemoveAll(target)
	if err != nil {
		t.Fatal(err)
	}

	_, err = os.Stat(outside)
	if err != nil {
		t.Fatalf("external file was removed: %v", err)
	}
}

func TestOpenDirectoryAtRetainsParentNamespace(t *testing.T) {
	root := t.TempDir()
	original := filepath.Join(root, "namespace")

	err := os.Mkdir(original, 0700)
	if err != nil {
		t.Fatal(err)
	}

	parent, err := OpenDirectory(root)
	if err != nil {
		t.Fatal(err)
	}

	defer parent.Close()

	err = os.Rename(original, filepath.Join(root, "old"))
	if err != nil {
		t.Fatal(err)
	}

	err = os.Mkdir(original, 0700)
	if err != nil {
		t.Fatal(err)
	}

	old, err := OpenDirectoryAt(parent, "old")
	if err != nil {
		t.Fatal(err)
	}

	old.Close()
}
