//go:build windows

package config

import (
	"path/filepath"
	"strings"
	"testing"

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
