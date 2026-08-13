//go:build !windows && !linux && !darwin

package disk

import (
	"os"

	"golang.org/x/sys/unix"
)

type mountIdentity uint64

func directoryMount(dir *os.File) (mountIdentity, error) {
	var st unix.Stat_t

	err := unix.Fstat(int(dir.Fd()), &st)
	return mountIdentity(st.Dev), err
}
