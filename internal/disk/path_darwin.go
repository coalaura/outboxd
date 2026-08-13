package disk

import (
	"os"
	"path/filepath"
)

var darwinNamespaceAliases = map[string]string{
	"/etc": "/private/etc",
	"/tmp": "/private/tmp",
	"/var": "/private/var",
}

func isLinkOrReparse(_ string, info os.FileInfo) (bool, error) {
	return info.Mode()&os.ModeSymlink != 0, nil
}

func allowNamespaceLink(path string) (bool, error) {
	want, ok := darwinNamespaceAliases[filepath.Clean(path)]
	if !ok {
		return false, nil
	}

	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return false, err
	}

	return filepath.Clean(resolved) == want, nil
}
