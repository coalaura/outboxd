//go:build !windows

package disk

import "os"

func mkdirDurableComponent(path string) (bool, error) {
	if err := os.Mkdir(path, 0700); err != nil {
		return false, err
	}
	return true, nil
}
