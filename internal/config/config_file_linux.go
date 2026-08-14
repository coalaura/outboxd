//go:build linux

package config

import (
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

func readConfigFile(path string, maximum int64) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}

	file := os.NewFile(uintptr(fd), path)
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, err
	}

	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%q must open as a regular file", path)
	}

	err = validateConfigPermissions(info)
	if err != nil {
		return nil, fmt.Errorf("%q: %w", path, err)
	}

	body, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}

	if int64(len(body)) > maximum {
		return nil, fmt.Errorf("%q exceeds %d-byte read limit", path, maximum)
	}

	return body, nil
}

func validateConfigPermissions(info os.FileInfo) error {
	permissions := info.Mode().Perm()
	if permissions&0077 == 0 {
		return nil
	}

	stat, ok := info.Sys().(*unix.Stat_t)
	if !ok || stat.Uid != 0 || permissions != 0440 || !processHasGroup(int(stat.Gid)) {
		return fmt.Errorf("permissions %04o allow group or other access", permissions)
	}

	return nil
}

func processHasGroup(gid int) bool {
	if os.Getegid() == gid {
		return true
	}

	groups, err := os.Getgroups()
	if err != nil {
		return false
	}

	for _, group := range groups {
		if group == gid {
			return true
		}
	}

	return false
}
