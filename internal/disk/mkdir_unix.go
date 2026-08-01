//go:build !windows

package disk

import "os"

func mkdirDurableComponent(path string) (bool, error) {
	err := os.Mkdir(path, 0700)
	if err != nil {
		return false, err
	}

	return true, nil
}
