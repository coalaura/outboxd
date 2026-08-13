//go:build linux

package disk

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

type mountIdentity uint64

func directoryMount(dir *os.File) (mountIdentity, error) {
	var stat unix.Statx_t

	err := unix.Statx(int(dir.Fd()), "", unix.AT_EMPTY_PATH|unix.AT_STATX_SYNC_AS_STAT, unix.STATX_MNT_ID, &stat)
	if err != nil {
		return 0, err
	}

	if stat.Mask&unix.STATX_MNT_ID == 0 {
		return 0, errors.New("statx did not return a mount ID")
	}

	return mountIdentity(stat.Mnt_id), nil
}
