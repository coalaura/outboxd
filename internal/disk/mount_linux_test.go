//go:build linux

package disk

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestRemoveAllRejectsBindMount(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("bind mounts require root")
	}

	root := t.TempDir()
	external := t.TempDir()

	mounted := filepath.Join(root, "mounted")

	err := os.Mkdir(mounted, 0700)
	if err != nil {
		t.Fatal(err)
	}

	outside := filepath.Join(external, "keep")

	err = os.WriteFile(outside, []byte("keep"), 0600)
	if err != nil {
		t.Fatal(err)
	}

	err = exec.Command("mount", "--bind", external, mounted).Run()
	if err != nil {
		t.Skipf("bind mount unavailable: %v", err)
	}

	t.Cleanup(func() {
		_ = exec.Command("umount", mounted).Run()
	})

	err = RemoveAll(root)
	if err == nil {
		t.Fatal("recursive removal crossed bind mount")
	}

	_, err = os.Stat(outside)
	if err != nil {
		t.Fatalf("external file was removed: %v", err)
	}
}
