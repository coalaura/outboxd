//go:build windows

package main

import (
	"fmt"

	"github.com/coalaura/outboxd/internal/windowsacl"
)

func prepareConfigPermissions(path string) error {
	return windowsacl.Repair(path, false)
}

func repairDeploymentPermissions(configPath, ownershipLockPath, mutationLockPath, dataPath string) error {
	err := windowsacl.Repair(ownershipLockPath, false)
	if err != nil {
		return fmt.Errorf("repair configuration ownership lock: %w", err)
	}

	err = windowsacl.Repair(mutationLockPath, false)
	if err != nil {
		return fmt.Errorf("repair configuration mutation lock: %w", err)
	}

	err = windowsacl.Repair(configPath, false)
	if err != nil {
		return fmt.Errorf("repair config permissions: %w", err)
	}

	return nil
}
