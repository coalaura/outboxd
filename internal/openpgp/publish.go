package openpgp

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	pgp "github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/coalaura/outboxd/internal/config"
	"github.com/coalaura/outboxd/internal/disk"
	"github.com/coalaura/outboxd/internal/mailbox"
	"golang.org/x/text/unicode/norm"
)

const zBase32Alphabet = "ybndrfg8ejkmcpqxot1uwisza345h769"

// PublishResult describes one identity included in a static publication bundle.
type PublishResult struct {
	Sender      string
	Fingerprint string
	PublicKey   string
	AdvancedWKD string
	DirectWKD   string
}

type publicationArtifact struct {
	path string
	body []byte
}

// Publish creates a complete, new static publication directory atomically.
func Publish(configPath, outputDirectory string) ([]PublishResult, error) {
	if strings.TrimSpace(outputDirectory) == "" {
		return nil, errors.New("output directory is empty")
	}

	cfg, err := config.LoadFile(configPath)
	if err != nil {
		return nil, err
	}

	identities, err := LoadPublic(cfg)
	if err != nil {
		return nil, err
	}

	target, err := filepath.Abs(filepath.Clean(outputDirectory))
	if err != nil {
		return nil, fmt.Errorf("resolve output directory: %w", err)
	}

	_, err = os.Lstat(target)
	if err == nil {
		return nil, fmt.Errorf("output directory already exists: %s", target)
	}

	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect output directory: %w", err)
	}

	parent := filepath.Dir(target)

	parentDirectory, err := disk.OpenDirectory(parent)
	if err != nil {
		return nil, fmt.Errorf("open output parent: %w", err)
	}

	err = parentDirectory.Close()
	if err != nil {
		return nil, fmt.Errorf("close output parent: %w", err)
	}

	temporary, err := os.MkdirTemp(parent, "."+filepath.Base(target)+".tmp-")
	if err != nil {
		return nil, fmt.Errorf("create publication directory: %w", err)
	}

	removeTemporary := true

	defer func() {
		if removeTemporary {
			_ = os.RemoveAll(temporary)
		}
	}()

	err = os.Chmod(temporary, 0755)
	if err != nil {
		return nil, fmt.Errorf("set publication directory mode: %w", err)
	}

	results, err := writePublication(temporary, identities)
	if err != nil {
		return nil, err
	}

	err = syncPublication(temporary)
	if err != nil {
		return nil, err
	}

	err = disk.RenameNoReplace(temporary, target)
	if err != nil {
		return nil, fmt.Errorf("commit publication directory: %w", err)
	}

	removeTemporary = false

	for i := range results {
		results[i].PublicKey = filepath.Join(target, results[i].PublicKey)
		results[i].AdvancedWKD = filepath.Join(target, results[i].AdvancedWKD)
		results[i].DirectWKD = filepath.Join(target, results[i].DirectWKD)
	}

	return results, nil
}

func writePublication(root string, identities []PublicIdentity) ([]PublishResult, error) {
	written := make(map[string][]byte)
	results := make([]PublishResult, 0, len(identities))

	var manifest strings.Builder

	manifest.WriteString("outboxd OpenPGP publication bundle\n\n")
	manifest.WriteString("Serve one WKD layout over HTTPS and publish fingerprints through a separate trusted channel.\n")
	manifest.WriteString("The advanced layout is preferred; the direct layout is provided for compatible deployments.\n\n")

	for _, identity := range identities {
		local, domain, err := splitSender(identity.Sender)
		if err != nil {
			return nil, err
		}

		hash := wkdHash(wkdLocalPart(local))

		fingerprintName := strings.ToLower(identity.Fingerprint) + ".asc"

		publicPath := filepath.Join("keys", fingerprintName)
		advancedPath := filepath.Join("wkd", "advanced", "openpgpkey."+domain, ".well-known", "openpgpkey", domain, "hu", hash)
		directPath := filepath.Join("wkd", "direct", domain, ".well-known", "openpgpkey", "hu", hash)

		armored, err := armorPublicKey(identity.Key)
		if err != nil {
			return nil, fmt.Errorf("armor public key for %q: %w", identity.Sender, err)
		}

		artifacts := []publicationArtifact{
			{publicPath, armored},
			{advancedPath, identity.Key},
			{directPath, identity.Key},
		}

		for _, artifact := range artifacts {
			err = writePublicArtifact(root, artifact.path, artifact.body, written)
			if err != nil {
				return nil, fmt.Errorf("publish %q: %w", identity.Sender, err)
			}
		}

		paths := []string{
			filepath.Join("wkd", "advanced", "openpgpkey."+domain, ".well-known", "openpgpkey", domain, "policy"),
			filepath.Join("wkd", "direct", domain, ".well-known", "openpgpkey", "policy"),
		}

		for _, policyPath := range paths {
			err = writePublicArtifact(root, policyPath, nil, written)
			if err != nil {
				return nil, fmt.Errorf("publish WKD policy for %q: %w", identity.Sender, err)
			}
		}

		fmt.Fprintf(&manifest, "%s\n  fingerprint %s\n", identity.Sender, identity.Fingerprint)
		fmt.Fprintf(&manifest, "  public key  %s\n", filepath.ToSlash(publicPath))
		fmt.Fprintf(&manifest, "  advanced    https://openpgpkey.%s/.well-known/openpgpkey/%s/hu/%s?l=%s\n", domain, domain, hash, url.QueryEscape(local))
		fmt.Fprintf(&manifest, "  direct      https://%s/.well-known/openpgpkey/hu/%s?l=%s\n\n", domain, hash, url.QueryEscape(local))

		results = append(results, PublishResult{
			Sender:      identity.Sender,
			Fingerprint: identity.Fingerprint,
			PublicKey:   publicPath,
			AdvancedWKD: advancedPath,
			DirectWKD:   directPath,
		})
	}

	err := writePublicArtifact(root, "MANIFEST.txt", []byte(manifest.String()), written)
	if err != nil {
		return nil, fmt.Errorf("write publication manifest: %w", err)
	}

	return results, nil
}

func writePublicArtifact(root, relative string, body []byte, written map[string][]byte) error {
	key := strings.ToLower(filepath.Clean(relative))
	if previous, ok := written[key]; ok {
		if !bytes.Equal(previous, body) {
			return fmt.Errorf("publication path collision at %s", filepath.ToSlash(relative))
		}

		return nil
	}

	written[key] = append([]byte(nil), body...)
	path := filepath.Join(root, relative)

	err := os.MkdirAll(filepath.Dir(path), 0755)
	if err != nil {
		return err
	}

	err = os.Chmod(filepath.Dir(path), 0755)
	if err != nil {
		return err
	}

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return err
	}

	_, writeErr := file.Write(body)
	if writeErr == nil {
		writeErr = file.Chmod(0644)
	}

	if writeErr == nil {
		writeErr = file.Sync()
	}

	closeErr := file.Close()
	if writeErr != nil {
		return writeErr
	}

	return closeErr
}

func syncPublication(root string) error {
	var directories []string

	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		if entry.IsDir() {
			err := os.Chmod(path, 0755)
			if err != nil {
				return err
			}

			directories = append(directories, path)
		}

		return nil
	})

	if err != nil {
		return fmt.Errorf("walk publication directory: %w", err)
	}

	sort.Slice(directories, func(i, j int) bool {
		return len(directories[i]) > len(directories[j])
	})

	for _, directory := range directories {
		err = disk.Sync(directory)
		if err != nil {
			return fmt.Errorf("sync publication directory %s: %w", directory, err)
		}
	}

	return nil
}

func armorPublicKey(key []byte) ([]byte, error) {
	var result bytes.Buffer

	armored, err := armor.Encode(&result, pgp.PublicKeyType, nil)
	if err != nil {
		return nil, err
	}

	_, err = armored.Write(key)
	if err == nil {
		err = armored.Close()
	} else {
		_ = armored.Close()
	}
	if err != nil {
		return nil, err
	}

	return result.Bytes(), nil
}

func splitSender(sender string) (string, string, error) {
	at := strings.LastIndexByte(sender, '@')
	if at <= 0 || at == len(sender)-1 {
		return "", "", fmt.Errorf("invalid sender %q", sender)
	}

	domain, err := mailbox.RoutingDomain(sender[at+1:])
	if err != nil {
		return "", "", fmt.Errorf("invalid publication domain for sender %q: %w", sender, err)
	}

	return sender[:at], domain, nil
}

func wkdLocalPart(local string) string {
	return strings.Map(func(value rune) rune {
		if value >= 'A' && value <= 'Z' {
			return value + ('a' - 'A')
		}

		return value
	}, local)
}

func wkdHash(local string) string {
	digest := sha1.Sum([]byte(local))

	var (
		encoded     [32]byte
		accumulator uint32
		bits        uint
		position    int
	)

	for _, value := range digest {
		accumulator = accumulator<<8 | uint32(value)
		bits += 8

		for bits >= 5 {
			bits -= 5
			encoded[position] = zBase32Alphabet[(accumulator>>bits)&31]
			position++
		}
	}

	return string(encoded[:])
}

// OpenPGPKeyOwner returns the RFC 7929 owner name for sender.
func OpenPGPKeyOwner(sender string) (string, error) {
	local, domain, err := splitSender(sender)
	if err != nil {
		return "", err
	}

	local = norm.NFC.String(local)
	digest := sha256.Sum256([]byte(local))

	return hex.EncodeToString(digest[:28]) + "._openpgpkey." + domain + ".", nil
}
