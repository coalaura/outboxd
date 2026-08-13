//go:build windows

package windowsacl

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var broadSIDs = []string{
	"S-1-1-0",      // Everyone
	"S-1-5-2",      // Network
	"S-1-5-4",      // Interactive
	"S-1-5-7",      // Anonymous
	"S-1-5-11",     // Authenticated Users
	"S-1-5-32-545", // Builtin Users
	"S-1-5-32-546", // Builtin Guests
	"S-1-5-32-547", // Builtin Power Users
	"S-1-15-2-1",   // All application packages
	"S-1-15-2-2",   // All restricted application packages
}

// Protect replaces path's DACL with inheritable full control for the current
// user, SYSTEM, and Administrators, and disables inheritance.
func Protect(path string, directory bool) error {
	sd, err := privateDescriptor(directory)
	if err != nil {
		return err
	}

	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("read private DACL: %w", err)
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
		return fmt.Errorf("protect DACL for %q: %w", path, err)
	}

	return nil
}

// SecurityAttributes returns a protected DACL suitable for secure creation.
func SecurityAttributes(directory bool) (*windows.SecurityAttributes, error) {
	sd, err := privateDescriptor(directory)
	if err != nil {
		return nil, err
	}

	return &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
	}, nil
}

func privateDescriptor(directory bool) (*windows.SECURITY_DESCRIPTOR, error) {
	user, err := currentUserSID()
	if err != nil {
		return nil, err
	}

	flags := ""

	if directory {
		flags = "OICI"
	}

	sddl := fmt.Sprintf("D:P(A;%s;FA;;;SY)(A;%s;FA;;;BA)(A;%s;FA;;;%s)", flags, flags, flags, user.String())

	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, fmt.Errorf("build private DACL: %w", err)
	}

	return sd, nil
}

// ValidateHandle rejects missing DACLs and access-granting ACEs which cannot be
// audited. Managed objects may grant access only to the current user, SYSTEM,
// and Administrators. Operator-managed objects reject broad readers/writers.
func ValidateHandle(handle windows.Handle, path string, managed bool, requireProtected bool) error {
	sd, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("read DACL for %q: %w", path, err)
	}

	control, _, err := sd.Control()
	if err != nil {
		return fmt.Errorf("read DACL control for %q: %w", path, err)
	}

	if requireProtected && control&windows.SE_DACL_PROTECTED == 0 {
		return fmt.Errorf("%q DACL inherits permissions; a protected DACL is required", path)
	}

	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("%q has no DACL and is accessible broadly: %w", path, err)
	}

	if dacl == nil {
		return fmt.Errorf("%q has a null DACL and is accessible broadly", path)
	}

	user, err := currentUserSID()
	if err != nil {
		return err
	}

	system, _ := windows.StringToSid("S-1-5-18")
	administrators, _ := windows.StringToSid("S-1-5-32-544")

	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("read owner for %q: %w", path, err)
	}

	if managed && !approvedOwner(owner, user, system, administrators) {
		return fmt.Errorf("%q has unexpected owner %s", path, owner.String())
	}

	for i := uint16(0); i < dacl.AceCount; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE

		err = windows.GetAce(dacl, uint32(i), &ace)
		if err != nil {
			return fmt.Errorf("read ACE %d for %q: %w", i, path, err)
		}

		if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}

		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return fmt.Errorf("%q has unsupported access-granting ACE type %d", path, ace.Header.AceType)
		}

		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if managed {
			if !sid.Equals(user) && !sid.Equals(system) && !sid.Equals(administrators) {
				return fmt.Errorf("%q DACL grants unexpected principal %s", path, sid.String())
			}

			continue
		}

		if dangerousAccess(ace.Mask) {
			if isBroadSID(sid) {
				return fmt.Errorf("%q DACL grants broad principal %s read or write access", path, sid.String())
			}

			if !sid.Equals(user) && !sid.Equals(system) && !sid.Equals(administrators) && !sid.Equals(owner) {
				return fmt.Errorf("%q DACL grants unexpected principal %s read or write access", path, sid.String())
			}
		}
	}

	return nil
}

func approvedOwner(owner, user, system, administrators *windows.SID) bool {
	return owner.Equals(user) || owner.Equals(system) || owner.Equals(administrators)
}

func currentUserSID() (*windows.SID, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("get current Windows user: %w", err)
	}

	return user.User.Sid, nil
}

func isBroadSID(sid *windows.SID) bool {
	for _, value := range broadSIDs {
		candidate, _ := windows.StringToSid(value)
		if sid.Equals(candidate) {
			return true
		}
	}

	return false
}

func dangerousAccess(mask windows.ACCESS_MASK) bool {
	const dataAccess = windows.FILE_READ_DATA | windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA

	return mask&(dataAccess|windows.GENERIC_READ|windows.GENERIC_WRITE|windows.GENERIC_ALL|windows.WRITE_DAC|windows.WRITE_OWNER) != 0
}
