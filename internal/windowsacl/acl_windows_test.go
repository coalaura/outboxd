//go:build windows

package windowsacl

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestValidateHandleRejectsBroadAccessAndAcceptsProtectedACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private.key")

	err := os.WriteFile(path, []byte("secret"), 0600)
	if err != nil {
		t.Fatal(err)
	}

	setTestDACL(t, path, "D:P(A;;FA;;;WD)")

	err = validatePath(path, false)
	if err == nil || !strings.Contains(err.Error(), "broad principal") {
		t.Fatalf("permissive DACL error=%v", err)
	}

	err = Protect(path, false)
	if err != nil {
		t.Fatal(err)
	}

	err = validatePath(path, true)
	if err != nil {
		t.Fatalf("protected private DACL rejected: %v", err)
	}
}

func setTestDACL(t *testing.T, path, sddl string) {
	t.Helper()

	sd, err := windows.SecurityDescriptorFromString(sddl)
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
}

func validatePath(path string, managed bool) error {
	ptr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}

	handle, err := windows.CreateFile(
		ptr,
		windows.READ_CONTROL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)

	if err != nil {
		return err
	}

	defer windows.CloseHandle(handle)

	return ValidateHandle(handle, path, managed, true)
}
