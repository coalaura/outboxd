//go:build windows

package config

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/coalaura/outboxd/internal/windowsacl"
	"golang.org/x/sys/windows"
)

func TestManagedConfigDACLCreationAndRejection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yml")

	_, created, err := EnsurePath(path)
	if err != nil || !created {
		t.Fatalf("create config: created=%t err=%v", created, err)
	}

	err = CheckFile(path, true)
	if err != nil {
		t.Fatalf("created config DACL rejected: %v", err)
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

	_, err = LoadFile(path)
	if err == nil || !strings.Contains(err.Error(), "unexpected principal") {
		t.Fatalf("permissive config DACL error=%v", err)
	}
}

func TestCheckGeneratedParentsRejectsJunction(t *testing.T) {
	data := filepath.Join(t.TempDir(), "data")

	err := os.Mkdir(data, 0700)
	if err != nil {
		t.Fatal(err)
	}

	err = windowsacl.Protect(data, true)
	if err != nil {
		t.Fatal(err)
	}

	external := t.TempDir()
	junction := filepath.Join(data, "generated")

	err = exec.Command("cmd", "/c", "mklink", "/J", junction, external).Run()
	if err != nil {
		t.Skipf("create directory junction: %v", err)
	}

	cfg := Config{}

	cfg.Server.DataDirectory = data

	err = cfg.CheckGeneratedParents(filepath.Join(junction, "key.pem"))
	if err == nil || !strings.Contains(err.Error(), "reparse") {
		t.Fatalf("junction error=%v", err)
	}
}
