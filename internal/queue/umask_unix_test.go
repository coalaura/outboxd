//go:build unix

package queue

import (
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestMain(m *testing.M) {
	previous := unix.Umask(0077)

	code := m.Run()

	unix.Umask(previous)

	os.Exit(code)
}
