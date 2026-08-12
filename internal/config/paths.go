package config

import (
	"errors"
	"path/filepath"
	"strings"
)

// Path returns the absolute config file path.
func (cfg *Config) Path() string {
	return cfg.path
}

// BaseDir returns the directory containing the config file.
func (cfg *Config) BaseDir() string {
	return cfg.baseDir
}

// ResolvePath resolves a path relative to the configured data directory.
// Relative data_directory values are resolved against the config file directory.
func (cfg Config) ResolvePath(path string) string {
	if filepath.IsAbs(path) {
		return path
	}

	data := cfg.Server.DataDirectory
	if !filepath.IsAbs(data) && cfg.baseDir != "" {
		data = filepath.Join(cfg.baseDir, data)
	}

	return filepath.Join(data, path)
}

// ResolveGeneratedPath confines generated DKIM and DNS files beneath data_directory.
func (cfg Config) ResolveGeneratedPath(path string) (string, error) {
	data, err := filepath.Abs(filepath.Clean(cfg.ResolvedDataDir()))
	if err != nil {
		return "", err
	}

	target := path
	if !filepath.IsAbs(target) {
		target = filepath.Join(data, target)
	}

	target, err = filepath.Abs(filepath.Clean(target))
	if err != nil {
		return "", err
	}

	rel, err := filepath.Rel(data, target)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", errors.New("path must resolve to a file beneath server.data_directory")
	}

	return target, nil
}

// ResolvedDataDir returns the absolute data directory.
func (cfg Config) ResolvedDataDir() string {
	data := cfg.Server.DataDirectory
	if filepath.IsAbs(data) {
		return data
	}

	if cfg.baseDir != "" {
		return filepath.Join(cfg.baseDir, data)
	}

	abs, err := filepath.Abs(data)
	if err != nil {
		return data
	}

	return abs
}
