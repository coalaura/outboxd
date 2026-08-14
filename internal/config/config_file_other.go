//go:build !linux

package config

func readConfigFile(path string, maximum int64) ([]byte, error) {
	return ReadCheckedFile(path, true, false, maximum)
}
