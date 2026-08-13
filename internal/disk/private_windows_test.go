//go:build windows

package disk

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/coalaura/outboxd/internal/windowsacl"
	"golang.org/x/sys/windows"
)

func TestEnsurePrivateRootCreatesProtectedTree(t *testing.T) {
	root := filepath.Join(t.TempDir(), "managed", "data")

	err := EnsurePrivateRoot(root)
	if err != nil {
		t.Fatal(err)
	}

	err = validatePrivateDirectory(root, true)
	if err != nil {
		t.Fatalf("created root is not protected: %v", err)
	}

	child := filepath.Join(root, "queue")

	err = MkdirDurable(child)
	if err != nil {
		t.Fatal(err)
	}

	err = ValidatePrivateDirectory(child)
	if err != nil {
		t.Fatalf("inherited child DACL is not private: %v", err)
	}
}

func TestEnsurePrivateRootRejectsPermissiveExistingRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "data")

	err := os.Mkdir(root, 0700)
	if err != nil {
		t.Fatal(err)
	}

	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}

	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}

	err = windows.SetNamedSecurityInfo(
		root,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		dacl,
		nil,
	)

	if err != nil {
		t.Fatal(err)
	}

	err = EnsurePrivateRoot(root)
	if err == nil || !strings.Contains(err.Error(), "unexpected principal") {
		t.Fatalf("permissive managed root error=%v", err)
	}
}

func TestLockCreatesProtectedFileAndRejectsPermissiveFile(t *testing.T) {
	root := filepath.Join(t.TempDir(), "data")

	err := EnsurePrivateRoot(root)
	if err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(root, ".lock")
	lock, err := Lock(path)
	if err != nil {
		t.Fatal(err)
	}

	err = lock.Close()
	if err != nil {
		t.Fatal(err)
	}

	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}

	err = windowsacl.ValidateHandle(windows.Handle(file.Fd()), path, true, true)
	if err != nil {
		file.Close()

		t.Fatalf("created lock DACL rejected: %v", err)
	}

	err = file.Close()
	if err != nil {
		t.Fatal(err)
	}

	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}

	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}

	err = windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		dacl,
		nil,
	)

	if err != nil {
		t.Fatal(err)
	}

	_, err = Lock(path)
	if err == nil || !strings.Contains(err.Error(), "unexpected principal") {
		t.Fatalf("permissive lock DACL error=%v", err)
	}
}

func TestValidatePrivateTreeRejectsDirectoryReparsePoint(t *testing.T) {
	root := filepath.Join(t.TempDir(), "data")

	err := EnsurePrivateRoot(root)
	if err != nil {
		t.Fatal(err)
	}

	target := t.TempDir()
	link := filepath.Join(root, "junction")

	err = exec.Command("cmd", "/c", "mklink", "/J", link, target).Run()
	if err != nil {
		t.Skipf("create directory junction: %v", err)
	}

	err = ValidatePrivateTree(root)
	if err == nil || !strings.Contains(err.Error(), "reparse point") {
		t.Fatalf("directory reparse point error=%v", err)
	}
}
