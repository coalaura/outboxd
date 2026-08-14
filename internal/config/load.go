package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/coalaura/outboxd/internal/disk"
	"github.com/goccy/go-yaml"
)

const maxConfigFileBytes = 1 << 20

// ResolveConfigPath picks the config path from flag/env/default.
func ResolveConfigPath(flagPath string) string {
	if flagPath != "" {
		return flagPath
	}

	v := os.Getenv(EnvConfigPath)
	if v != "" {
		return v
	}

	return defaultConfigName
}

// LoadFile loads configuration from path.
func LoadFile(path string) (*Config, error) {
	cfg := Default()

	cfg.initializeRuntime()

	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}

	cfg.path = abs
	cfg.baseDir = filepath.Dir(abs)

	raw, err := readConfigFile(abs, maxConfigFileBytes)
	if err != nil {
		return nil, fmt.Errorf("config file: %w", err)
	}

	err = rejectMultiDoc(raw)
	if err != nil {
		return nil, err
	}

	cfg.Users = nil

	dec := yaml.NewDecoder(bytes.NewReader(raw), yaml.DisallowUnknownField())

	err = dec.Decode(cfg)
	if err != nil {
		return nil, err
	}

	var extra any

	err = dec.Decode(&extra)
	if err == nil {
		return nil, errors.New("config contains trailing YAML content")
	} else if err != io.EOF && !isYAMLEOF(err) {
		return nil, fmt.Errorf("trailing YAML content: %w", err)
	}

	cfg.applyDefaults()

	err = cfg.Init()
	if err != nil {
		return nil, err
	}

	return cfg, nil
}

// Load loads from the default path resolution.
func Load() (*Config, error) {
	return LoadFile(ResolveConfigPath(""))
}

// Ensure loads the config or atomically creates it with secure defaults.
func Ensure() (*Config, bool, error) {
	return EnsurePath(ResolveConfigPath(""))
}

// EnsurePath loads or creates config at path.
func EnsurePath(path string) (*Config, bool, error) {
	cfg, err := LoadFile(path)
	if err == nil {
		return cfg, false, nil
	}

	if !errors.Is(err, os.ErrNotExist) {
		return nil, false, err
	}

	cfg = Default()

	cfg.initializeRuntime()

	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, false, err
	}

	cfg.path = abs
	cfg.baseDir = filepath.Dir(abs)

	cfg.applyDefaults()

	err = cfg.Init()
	if err != nil {
		return nil, false, err
	}

	err = cfg.storeExclusive()
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			cfg, err = LoadFile(path)

			return cfg, false, err
		}

		return nil, false, err
	}

	return cfg, true, nil
}

// UpdateFile atomically rewrites an existing config with current defaults.
func UpdateFile(path string) (*Config, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}

	// Confirm the config exists before creating its mutation lock file.
	_, err = LoadFile(abs)
	if err != nil {
		return nil, err
	}

	lock, err := lockConfig(abs + ".lock")
	if err != nil {
		return nil, err
	}

	defer lock.Close()

	latest, err := LoadFile(abs)
	if err != nil {
		return nil, fmt.Errorf("reload config under mutation lock: %w", err)
	}

	err = latest.Save()
	if err != nil {
		return nil, err
	}

	return latest, nil
}

// LockForMutation requires an existing valid config, takes its cross-process
// mutation lock and reloads the owned snapshot.
func LockForMutation(path string) (*Config, *disk.FileLock, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, nil, err
	}

	// Do not create a lock file for a missing or already invalid config.
	_, err = LoadFile(abs)
	if err != nil {
		return nil, nil, err
	}

	lock, err := lockConfig(abs + ".lock")
	if err != nil {
		return nil, nil, err
	}

	latest, err := LoadFile(abs)
	if err != nil {
		_ = lock.Close()

		return nil, nil, fmt.Errorf("reload config under mutation lock: %w", err)
	}

	return latest, lock, nil
}

func isYAMLEOF(err error) bool {
	return err != nil && (errors.Is(err, io.EOF) || strings.Contains(err.Error(), "EOF"))
}

func rejectMultiDoc(raw []byte) error {
	var count int

	for line := range bytes.SplitSeq(raw, []byte("\n")) {
		if bytes.Equal(bytes.TrimSpace(line), []byte("---")) {
			count++

			if count > 1 {
				return errors.New("config contains multiple YAML documents")
			}
		}
	}

	return nil
}
