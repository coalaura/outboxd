package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/coalaura/outboxd/internal/config"
	"github.com/coalaura/outboxd/internal/disk"
)

func repairPermissions(configPath string) error {
	path, err := filepath.Abs(config.ResolveConfigPath(configPath))
	if err != nil {
		return err
	}

	info, err := os.Lstat(path)
	if err != nil {
		return err
	}

	if !info.Mode().IsRegular() {
		return fmt.Errorf("config must be a regular file: %s", path)
	}

	lockPath := path + ".outboxd.lock"

	info, err = os.Lstat(lockPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}

	if err == nil && !info.Mode().IsRegular() {
		return fmt.Errorf("configuration ownership lock is not a regular file: %s", lockPath)
	}

	ownership, err := disk.LockForRepair(lockPath)
	if err != nil {
		return fmt.Errorf("configuration %s: %w: stop the running daemon before repairing permissions", path, err)
	}

	defer ownership.Close()

	mutationLockPath := path + ".lock"

	info, err = os.Lstat(mutationLockPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}

	if err == nil && !info.Mode().IsRegular() {
		return fmt.Errorf("configuration mutation lock is not a regular file: %s", mutationLockPath)
	}

	mutation, err := disk.LockForRepair(mutationLockPath)
	if err != nil {
		return fmt.Errorf("configuration mutation lock %s: %w: stop configuration updates before repairing permissions", mutationLockPath, err)
	}

	defer mutation.Close()

	err = prepareConfigPermissions(path)
	if err != nil {
		return fmt.Errorf("prepare config permissions: %w", err)
	}

	cfg, err := config.LoadFile(path)
	if err != nil {
		return err
	}

	err = disk.ValidatePath(cfg.ResolvedDataDir())
	if err != nil {
		return fmt.Errorf("validate data namespace %s: %w", cfg.ResolvedDataDir(), err)
	}

	spoolOwnership, err := lockSpoolForRepair(cfg)
	if err != nil {
		return err
	}

	defer spoolOwnership.Close()

	err = disk.RepairPrivateTree(cfg.ResolvedDataDir())
	if err != nil {
		return fmt.Errorf("repair private data directory: %w", err)
	}

	err = repairDeploymentPermissions(path, lockPath, mutationLockPath, cfg.ResolvedDataDir())
	if err != nil {
		return err
	}

	_, err = config.LoadFile(path)
	if err != nil {
		return fmt.Errorf("validate repaired config: %w", err)
	}

	err = disk.ValidatePrivateDirectory(cfg.ResolvedDataDir())
	if err != nil {
		return fmt.Errorf("validate repaired data directory: %w", err)
	}

	err = disk.ValidatePrivateTree(cfg.ResolvedDataDir())
	if err != nil {
		return fmt.Errorf("validate repaired data tree: %w", err)
	}

	fmt.Fprintf(os.Stdout, "Repaired permissions for config %q and managed data %q.\n", path, cfg.ResolvedDataDir())

	return nil
}

func lockSpoolForRepair(cfg *config.Config) (*disk.FileLock, error) {
	queuePath := cfg.ResolvePath("queue")

	err := disk.ValidatePath(queuePath)
	if err != nil {
		return nil, fmt.Errorf("validate spool namespace %s: %w", queuePath, err)
	}

	info, err := os.Stat(queuePath)
	if err != nil {
		return nil, fmt.Errorf("spool is not provisioned at %s: %w", queuePath, err)
	}

	if !info.IsDir() {
		return nil, fmt.Errorf("spool path is not a directory: %s", queuePath)
	}

	lock, err := disk.LockForRepair(filepath.Join(queuePath, ".lock"))
	if err != nil {
		return nil, fmt.Errorf("spool %s: %w: stop the running daemon before repairing permissions", queuePath, err)
	}

	return lock, nil
}
