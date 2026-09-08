//go:build !windows

package main

import (
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func prepareConfigPermissions(path string) error {
	return repairUnixFile(path, -1, -1, 0600)
}

func repairDeploymentPermissions(configPath, ownershipLockPath, mutationLockPath, dataPath string) error {
	info, err := os.Stat(dataPath)
	if err != nil {
		return fmt.Errorf("inspect data directory owner: %w", err)
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errorsUnsupportedOwner(dataPath)
	}

	uid := int(stat.Uid)
	gid := int(stat.Gid)

	err = repairUnixFile(ownershipLockPath, uid, gid, 0600)
	if err != nil {
		return fmt.Errorf("repair configuration ownership lock: %w", err)
	}

	err = repairUnixFile(mutationLockPath, uid, gid, 0600)
	if err != nil {
		return fmt.Errorf("repair configuration mutation lock: %w", err)
	}

	configUID := uid
	configMode := os.FileMode(0600)

	if os.Geteuid() == 0 {
		configUID = 0
		configMode = 0440
	}

	err = repairUnixFile(configPath, configUID, gid, configMode)
	if err != nil {
		return fmt.Errorf("repair config ownership and permissions: %w", err)
	}

	return nil
}

func repairUnixFile(path string, uid, gid int, mode os.FileMode) error {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}

	file := os.NewFile(uintptr(fd), path)
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return err
	}

	if !info.Mode().IsRegular() {
		return fmt.Errorf("%q is not a regular file", path)
	}

	if uid >= 0 {
		err = unix.Fchown(fd, uid, gid)
		if err != nil {
			return err
		}
	}

	return file.Chmod(mode)
}

func errorsUnsupportedOwner(path string) error {
	return fmt.Errorf("cannot determine owner of %q", path)
}
