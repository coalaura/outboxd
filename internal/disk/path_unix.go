//go:build !windows && !darwin

package disk

import "os"

func isLinkOrReparse(_ string, info os.FileInfo) (bool, error) {
	return info.Mode()&os.ModeSymlink != 0, nil
}

func allowNamespaceLink(string) (bool, error) {
	return false, nil
}
