//go:build windows

package disk

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestRemoveAllDoesNotCrossJunction(t *testing.T) {
	root := filepath.Join(t.TempDir(), "root")

	err := os.Mkdir(root, 0700)
	if err != nil {
		t.Fatal(err)
	}

	external := t.TempDir()
	outside := filepath.Join(external, "keep")

	err = os.WriteFile(outside, []byte("keep"), 0600)
	if err != nil {
		t.Fatal(err)
	}

	err = exec.Command("cmd", "/c", "mklink", "/J", filepath.Join(root, "junction"), external).Run()
	if err != nil {
		t.Skipf("create directory junction: %v", err)
	}

	err = RemoveAll(root)
	if err != nil {
		t.Fatal(err)
	}

	_, err = os.Stat(outside)
	if err != nil {
		t.Fatalf("external file was removed: %v", err)
	}
}
