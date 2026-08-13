//go:build darwin

package disk

import (
	"os"

	"golang.org/x/sys/unix"
)

type mountIdentity struct {
	fsid unix.Fsid
	dev  int32
}

func directoryMount(dir *os.File) (mountIdentity, error) {
	var fs unix.Statfs_t

	err := unix.Fstatfs(int(dir.Fd()), &fs)
	if err != nil {
		return mountIdentity{}, err
	}

	var st unix.Stat_t

	err = unix.Fstat(int(dir.Fd()), &st)
	if err != nil {
		return mountIdentity{}, err
	}

	return mountIdentity{fsid: fs.Fsid, dev: st.Dev}, nil
}
