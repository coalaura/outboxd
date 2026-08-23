package openpgp

import (
	"bytes"
	"context"
	"crypto"
	"errors"
	"fmt"
	"io"
	"net/mail"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	pgp "github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/coalaura/outboxd/internal/config"
	"github.com/coalaura/outboxd/internal/disk"
	"github.com/coalaura/outboxd/internal/mailbox"
)

// Recipients is an immutable startup snapshot of static recipient public keys.
type Recipients struct {
	keys     map[string]*pgp.Entity
	required map[string]struct{}
	maximum  int64
}

// KeyID reports the stable key identity selected for recipient. Equal IDs may
// safely share one ciphertext variant.
func (r *Recipients) KeyID(recipient string) (string, bool, error) {
	if r == nil {
		return "", false, nil
	}

	recipient, err := mailbox.CanonicalAddress(recipient)
	if err != nil {
		return "", false, fmt.Errorf("canonicalize recipient %q: %w", recipient, err)
	}

	entity := r.keys[recipient]
	if entity == nil {
		if _, required := r.required[recipient]; required {
			return "", false, fmt.Errorf("required encryption recipient %q has no usable key", recipient)
		}

		return "", false, nil
	}

	encryptionKey, ok := entity.EncryptionKey(time.Now())
	if !ok {
		return "", false, fmt.Errorf("recipient %q no longer has a usable encryption key", recipient)
	}

	return fmt.Sprintf("%X", encryptionKey.PublicKey.Fingerprint), true, nil
}

// LoadRecipients reads and validates static recipient public keys.
func LoadRecipients(cfg *config.Config) (*Recipients, error) {
	recipients := &Recipients{
		keys:     make(map[string]*pgp.Entity),
		required: make(map[string]struct{}, len(cfg.OpenPGP.RequireEncryptionFor)),
		maximum:  cfg.Server.MaxMessageBytes,
	}

	for _, address := range cfg.OpenPGP.RequireEncryptionFor {
		canonical, err := mailbox.CanonicalAddress(address)
		if err != nil {
			return nil, fmt.Errorf("canonicalize required encryption recipient %q: %w", address, err)
		}

		recipients.required[canonical] = struct{}{}
	}

	configured := cfg.OpenPGP.RecipientKeysDirectory
	if configured == "" {
		return recipients, nil
	}

	directory := cfg.ResolvePath(configured)

	if !filepath.IsAbs(configured) {
		err := cfg.CheckGeneratedParents(filepath.Join(directory, "recipient-key"))
		if err != nil {
			return nil, fmt.Errorf("check recipient key directory: %w", err)
		}
	}

	err := disk.ValidatePath(directory)
	if err != nil {
		return nil, fmt.Errorf("validate recipient key directory: %w", err)
	}

	err = disk.ValidatePrivateDirectory(directory)
	if err != nil {
		return nil, fmt.Errorf("validate recipient key directory: %w", err)
	}

	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, fmt.Errorf("read recipient key directory: %w", err)
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() < entries[j].Name()
	})

	var keyFiles int

	for _, entry := range entries {
		extension := strings.ToLower(filepath.Ext(entry.Name()))
		if extension != ".asc" && extension != ".pgp" {
			continue
		}

		keyFiles++
		if keyFiles > config.MaxOpenPGPRecipientKeys {
			return nil, fmt.Errorf("recipient key directory contains more than %d key files", config.MaxOpenPGPRecipientKeys)
		}

		path := filepath.Join(directory, entry.Name())

		entity, addresses, err := readRecipientEntity(path)
		if err != nil {
			return nil, fmt.Errorf("recipient key %q: %w", entry.Name(), err)
		}

		for _, address := range addresses {
			if _, exists := recipients.keys[address]; exists {
				return nil, fmt.Errorf("recipient address %q is present in multiple key files", address)
			}

			recipients.keys[address] = entity
		}
	}

	for address := range recipients.required {
		if recipients.keys[address] == nil {
			return nil, fmt.Errorf("required encryption recipient %q has no usable static key", address)
		}
	}

	return recipients, nil
}

func readRecipientEntity(path string) (*pgp.Entity, []string, error) {
	keyData, err := config.ReadCheckedFile(path, true, false, maxKeyBytes)
	if err != nil {
		return nil, nil, err
	}

	defer clear(keyData)

	entities, err := pgp.ReadArmoredKeyRing(bytes.NewReader(keyData))
	if err != nil {
		entities, err = pgp.ReadKeyRing(bytes.NewReader(keyData))
	}

	if err != nil {
		return nil, nil, fmt.Errorf("parse public key: %w", err)
	}

	if len(entities) != 1 {
		return nil, nil, fmt.Errorf("key file must contain exactly one entity, got %d", len(entities))
	}

	entity := entities[0]
	if entity.PrivateKey != nil {
		return nil, nil, errors.New("key file contains private key material")
	}

	for _, subkey := range entity.Subkeys {
		if subkey.PrivateKey != nil {
			return nil, nil, errors.New("key file contains private key material")
		}
	}

	now := time.Now()

	encryptionKey, ok := entity.EncryptionKey(now)
	if !ok {
		return nil, nil, errors.New("key has no currently valid encryption key")
	}

	if !encryptionKey.PublicKey.PubKeyAlgo.CanEncrypt() {
		return nil, nil, errors.New("selected key algorithm cannot encrypt")
	}

	if !supportedEncryptionAlgorithm(encryptionKey.PublicKey.PubKeyAlgo) {
		return nil, nil, errors.New("selected key uses an unsupported encryption algorithm")
	}

	if encryptionKey.PublicKey.PubKeyAlgo == packet.PubKeyAlgoRSA || encryptionKey.PublicKey.PubKeyAlgo == packet.PubKeyAlgoRSAEncryptOnly {
		bits, err := encryptionKey.PublicKey.BitLength()
		if err != nil || bits < 2048 {
			return nil, nil, errors.New("RSA encryption key must be at least 2048 bits")
		}
	}

	addresses := make(map[string]struct{})

	for _, identity := range entity.Identities {
		if identity.UserId == nil || identity.SelfSignature == nil || identity.SelfSignature.SigExpired(now) || identity.Revoked(now) {
			continue
		}

		err = entity.PrimaryKey.VerifyUserIdSignature(identity.UserId.Id, entity.PrimaryKey, identity.SelfSignature)
		if err != nil {
			return nil, nil, fmt.Errorf("verify user ID self-signature: %w", err)
		}

		parsed, err := mail.ParseAddress(identity.Name)
		if err != nil {
			continue
		}

		address, err := mailbox.CanonicalAddress(parsed.Address)
		if err != nil {
			continue
		}

		addresses[address] = struct{}{}
	}

	if len(addresses) == 0 {
		return nil, nil, errors.New("key has no active supported email identity")
	}

	result := make([]string, 0, len(addresses))

	for address := range addresses {
		result = append(result, address)
	}

	sort.Strings(result)

	return entity, result, nil
}

// Encrypt wraps data in multipart/encrypted using the identity returned by
// KeyID. A configured-key failure never falls back to plaintext.
func (r *Recipients) Encrypt(ctx context.Context, recipient, keyID string, data []byte) ([]byte, bool, error) {
	if r == nil {
		return data, false, nil
	}

	recipient, err := mailbox.CanonicalAddress(recipient)
	if err != nil {
		return nil, false, fmt.Errorf("canonicalize recipient %q: %w", recipient, err)
	}

	entity := r.keys[recipient]
	if entity == nil {
		return data, false, nil
	}

	now := time.Now()

	encryptionKey, ok := entity.EncryptionKey(now)
	if !ok {
		return nil, false, fmt.Errorf("recipient %q no longer has a usable encryption key", recipient)
	}

	if actual := fmt.Sprintf("%X", encryptionKey.PublicKey.Fingerprint); actual != keyID {
		return nil, false, fmt.Errorf("recipient %q encryption key changed during preparation", recipient)
	}

	if err := ctx.Err(); err != nil {
		return nil, false, err
	}

	outer, mimeEntity, err := splitMessage(data, false)
	if err != nil {
		return nil, false, err
	}

	boundary, err := randomBoundary()
	if err != nil {
		return nil, false, err
	}

	encrypted := limitedBuffer{maximum: r.maximum, ctx: ctx}

	armored, err := armor.Encode(&encrypted, "PGP MESSAGE", nil)
	if err != nil {
		return nil, false, fmt.Errorf("create armored message: %w", err)
	}

	cryptoConfig := encryptionConfig()

	cryptoConfig.Time = func() time.Time {
		return now
	}

	plaintext, err := pgp.Encrypt(armored, []*pgp.Entity{entity}, nil, nil, cryptoConfig)
	if err != nil {
		_ = armored.Close()

		return nil, false, fmt.Errorf("initialize encryption for %q: %w", recipient, err)
	}

	_, err = io.Copy(plaintext, contextReader{ctx: ctx, reader: bytes.NewReader(mimeEntity)})
	if err == nil {
		err = plaintext.Close()
	}

	if err == nil {
		err = armored.Close()
	} else {
		_ = plaintext.Close()
		_ = armored.Close()
	}

	if err != nil {
		if ctx.Err() != nil {
			return nil, false, ctx.Err()
		}

		return nil, false, fmt.Errorf("encrypt for %q: %w", recipient, err)
	}

	armorData := bytes.ReplaceAll(encrypted.Bytes(), []byte("\r\n"), []byte("\n"))
	armorData = bytes.ReplaceAll(armorData, []byte("\n"), []byte("\r\n"))

	result := buildEncryptedMessage(outer, armorData, boundary)
	if int64(len(result)) > r.maximum {
		return nil, false, fmt.Errorf("%w: maximum is %d bytes", ErrMessageTooLarge, r.maximum)
	}

	return result, true, nil
}

func encryptionConfig() *packet.Config {
	return &packet.Config{
		DefaultHash:   crypto.SHA256,
		DefaultCipher: packet.CipherAES256,
		MinRSABits:    2048,
	}
}

func supportedEncryptionAlgorithm(algorithm packet.PublicKeyAlgorithm) bool {
	switch algorithm {
	case packet.PubKeyAlgoRSA, packet.PubKeyAlgoRSAEncryptOnly, packet.PubKeyAlgoECDH, packet.PubKeyAlgoX25519, packet.PubKeyAlgoX448:
		return true
	default:
		return false
	}
}

func buildEncryptedMessage(outer, encrypted []byte, boundary string) []byte {
	var result bytes.Buffer
	result.Grow(len(outer) + len(encrypted) + 512)

	result.Write(outer)
	result.WriteString("MIME-Version: 1.0\r\n")
	result.WriteString("Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=\"")
	result.WriteString(boundary)
	result.WriteString("\"\r\n\r\nThis is an OpenPGP/MIME encrypted message.\r\n\r\n--")
	result.WriteString(boundary)
	result.WriteString("\r\nContent-Type: application/pgp-encrypted\r\n\r\nVersion: 1\r\n\r\n--")
	result.WriteString(boundary)
	result.WriteString("\r\nContent-Type: application/octet-stream; name=\"encrypted.asc\"\r\n")
	result.WriteString("Content-Disposition: inline; filename=\"encrypted.asc\"\r\n\r\n")
	result.Write(encrypted)
	result.WriteString("\r\n--")
	result.WriteString(boundary)
	result.WriteString("--\r\n")

	return result.Bytes()
}
