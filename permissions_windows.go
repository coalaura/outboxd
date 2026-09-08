//go:build windows

package main

import (
	"fmt"

	"github.com/coalaura/outboxd/internal/windowsacl"
)

func prepareConfigPermissions(path string) error {
	return windowsacl.Repair(path, false)
}

func repairDeploymentPermissions(configPath, lockPath, dataPath string) error {
	err := windowsacl.Repair(lockPath, false)
	if err != nil {
		return fmt.Errorf("repair configuration ownership lock: %w", err)
	}

	err = windowsacl.Repair(configPath, false)
	if err != nil {
		return fmt.Errorf("repair config permissions: %w", err)
	}

	return nil
}
