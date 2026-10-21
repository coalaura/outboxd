package openpgp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	pgp "github.com/ProtonMail/go-crypto/openpgp"
	"github.com/coalaura/outboxd/internal/config"
	"github.com/coalaura/outboxd/internal/disk"
)

const wkdCacheLifetime = 24 * time.Hour

type wkdCacheEntry struct {
	Recipient string    `json:"recipient"`
	FetchedAt time.Time `json:"fetched_at"`
	Key       []byte    `json:"key"`
}

func loadWKDRecipient(ctx context.Context, cfg *config.Config, recipient string, lookup func(context.Context, string) ([]byte, error)) (*pgp.Entity, error) {
	path, err := wkdCachePath(cfg, recipient)
	if err != nil {
		return nil, fmt.Errorf("validate WKD cache: %w", err)
	}

	entity, err := readWKDCache(path, recipient)
	if err != nil {
		return nil, fmt.Errorf("read WKD cache: %w", err)
	}

	if entity != nil {
		return entity, nil
	}

	keyData, err := lookup(ctx, recipient)
	if err != nil {
		return nil, err
	}

	defer clear(keyData)

	entity, err = parseWKDRecipient(keyData, recipient)
	if err != nil {
		return nil, fmt.Errorf("validate WKD key: %w", err)
	}

	err = ctx.Err()
	if err != nil {
		return nil, err
	}

	entry := wkdCacheEntry{Recipient: recipient, FetchedAt: time.Now().UTC(), Key: keyData}

	body, err := json.Marshal(entry)
	if err != nil {
		return nil, err
	}

	_, err = wkdCachePath(cfg, recipient)
	if err != nil {
		return nil, err
	}

	err = disk.MkdirDurable(filepath.Dir(path))
	if err != nil {
		return nil, fmt.Errorf("create WKD cache: %w", err)
	}

	// Recheck the created namespace before writing through the atomic private
	// file helper, including protected DACL validation on Windows.
	_, err = wkdCachePath(cfg, recipient)
	if err != nil {
		return nil, err
	}

	err = disk.Write(path, body, 0600)
	if err != nil {
		return nil, fmt.Errorf("write WKD cache: %w", err)
	}

	return entity, nil
}

func wkdCachePath(cfg *config.Config, recipient string) (string, error) {
	configured := cfg.OpenPGP.WKDCacheDirectory
	if configured == "" {
		configured = "openpgp/cache"
	}

	directory, err := cfg.ResolveGeneratedPath(configured)
	if err != nil {
		return "", err
	}

	digest := sha256.Sum256([]byte(recipient))
	path := filepath.Join(directory, hex.EncodeToString(digest[:])+".json")

	err = disk.ValidatePath(path)
	if err != nil {
		return "", err
	}

	for current := directory; ; current = filepath.Dir(current) {
		relative, err := filepath.Rel(cfg.ResolvedDataDir(), current)
		if err != nil {
			return "", err
		}

		err = disk.ValidatePrivateDirectory(current)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return "", err
		}

		if relative == "." {
			break
		}
	}

	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return path, nil
	}

	if err != nil {
		return "", err
	}

	if !info.Mode().IsRegular() {
		return "", errors.New("WKD cache entry must be a regular file")
	}

	err = config.CheckFile(path, true)
	return path, err
}

func readWKDCache(path, recipient string) (*pgp.Entity, error) {
	body, err := config.ReadCheckedFile(path, true, false, 2*wkdMaxKeyBytes)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}

	if err != nil {
		return nil, err
	}

	var entry wkdCacheEntry

	err = json.Unmarshal(body, &entry)
	if err != nil {
		return nil, err
	}

	if entry.Recipient != recipient {
		return nil, errors.New("WKD cache recipient mismatch")
	}

	age := time.Since(entry.FetchedAt)
	if age < 0 || age >= wkdCacheLifetime {
		return nil, nil
	}

	// Expired or revoked cached keys require fresh discovery; stale keys never
	// rescue a failed lookup. The selected key is checked again at submission.
	entity, err := parseWKDRecipient(entry.Key, recipient)
	if err != nil {
		return nil, nil
	}

	return entity, nil
}
