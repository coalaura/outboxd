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

func TestApprovedOwnerRejectsForeignPrincipal(t *testing.T) {
	user, err := currentUserSID()
	if err != nil {
		t.Fatal(err)
	}

	system, _ := windows.StringToSid("S-1-5-18")
	administrators, _ := windows.StringToSid("S-1-5-32-544")
	foreign, _ := windows.StringToSid("S-1-1-0")

	if approvedOwner(foreign, user, system, administrators) {
		t.Fatal("foreign owner accepted")
	}

	for _, owner := range []*windows.SID{user, system, administrators} {
		if !approvedOwner(owner, user, system, administrators) {
			t.Fatalf("approved owner %s rejected", owner.String())
		}
	}
}

func TestValidateHandleRejectsForeignOwner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "foreign-owner")

	err := os.WriteFile(path, []byte("secret"), 0600)
	if err != nil {
		t.Fatal(err)
	}

	err = Protect(path, false)
	if err != nil {
		t.Fatal(err)
	}

	user, err := currentUserSID()
	if err != nil {
		t.Fatal(err)
	}

	foreign, _ := windows.StringToSid("S-1-1-0")

	err = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, foreign, nil, nil, nil)
	if err != nil {
		t.Skipf("changing file owner requires additional privilege: %v", err)
	}

	t.Cleanup(func() {
		_ = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, user, nil, nil, nil)
	})

	err = validatePath(path, true)
	if err == nil || !strings.Contains(err.Error(), "unexpected owner") {
		t.Fatalf("foreign owner error=%v", err)
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
