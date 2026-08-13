//go:build windows

package disk

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/coalaura/outboxd/internal/windowsacl"
	"golang.org/x/sys/windows"
)

func mkdirDurableComponent(path string) (bool, error) {
	attributes, err := windowsacl.SecurityAttributes(true)
	if err != nil {
		return false, err
	}

	var temp string

	for attempt := range 100 {
		var random [8]byte

		_, err := rand.Read(random[:])
		if err != nil {
			return false, err
		}

		temp = filepath.Join(filepath.Dir(path), ".outboxd-mkdir-"+hex.EncodeToString(random[:]))

		ptr, err := windows.UTF16PtrFromString(temp)
		if err != nil {
			return false, err
		}

		err = windows.CreateDirectory(ptr, attributes)
		if err == nil {
			break
		}

		if !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			return false, err
		}

		if attempt == 99 {
			return false, fmt.Errorf("create private temporary directory: %w", err)
		}
	}

	remove := true

	defer func() {
		if remove {
			_ = os.Remove(temp)
		}
	}()

	oldptr, err := windows.UTF16PtrFromString(temp)
	if err != nil {
		return false, err
	}

	newptr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false, err
	}

	err = windows.MoveFileEx(oldptr, newptr, windows.MOVEFILE_WRITE_THROUGH)
	if err != nil {
		if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			return false, os.ErrExist
		}

		return false, err
	}

	remove = false

	return true, nil
}
