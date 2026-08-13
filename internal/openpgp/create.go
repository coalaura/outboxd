package openpgp

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	pgp "github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/ProtonMail/go-crypto/openpgp/s2k"
	"github.com/coalaura/outboxd/internal/config"
	"github.com/coalaura/outboxd/internal/disk"
	"github.com/coalaura/outboxd/internal/mailbox"
)

const generatedRSABits = 3072

// CreatedKey identifies material installed by Create.
type CreatedKey struct {
	Sender         string
	Fingerprint    string
	SigningKey     string
	PassphraseFile string
}

type generatedKey struct {
	armoredKey  []byte
	passphrase  []byte
	fingerprint string
}

// Create generates and configures an encrypted private key for one exact
// sender already authorized for username.
func Create(configPath, username, sender string) (*CreatedKey, error) {
	sender, err := canonicalSender(sender)
	if err != nil {
		return nil, err
	}

	initial, err := config.LoadFile(configPath)
	if err != nil {
		return nil, err
	}

	err = validateCreate(initial, username, sender)
	if err != nil {
		return nil, err
	}

	generated, err := generateKey(sender)
	if err != nil {
		return nil, err
	}

	defer clear(generated.passphrase)
	defer clear(generated.armoredKey)

	latest, lock, err := config.LockForMutation(configPath)
	if err != nil {
		return nil, err
	}

	defer lock.Close()

	err = validateCreate(latest, username, sender)
	if err != nil {
		return nil, err
	}

	base := strings.ToLower(generated.fingerprint)

	keyRelative := filepath.ToSlash(filepath.Join("openpgp", base+".private.asc"))
	passRelative := filepath.ToSlash(filepath.Join("openpgp", base+".passphrase"))

	keyPath, err := latest.ResolveGeneratedPath(keyRelative)
	if err != nil {
		return nil, err
	}

	passPath, err := latest.ResolveGeneratedPath(passRelative)
	if err != nil {
		return nil, err
	}

	dataDir := latest.ResolvedDataDir()

	err = disk.ValidatePath(dataDir)
	if err != nil {
		return nil, fmt.Errorf("validate private data directory: %w", err)
	}

	err = disk.EnsurePrivateRoot(dataDir)
	if err != nil {
		return nil, fmt.Errorf("prepare private data directory: %w", err)
	}

	err = disk.EnsurePrivateRoot(filepath.Dir(keyPath))
	if err != nil {
		return nil, fmt.Errorf("prepare private OpenPGP directory: %w", err)
	}

	err = latest.CheckGeneratedParents(keyPath)
	if err != nil {
		return nil, fmt.Errorf("check generated OpenPGP path: %w", err)
	}

	err = disk.WriteExclusive(keyPath, generated.armoredKey, 0600)
	if err != nil {
		writeErr := fmt.Errorf("write OpenPGP private key: %w", err)
		if errors.Is(err, os.ErrExist) {
			return nil, writeErr
		}

		return nil, errors.Join(writeErr, rollbackGenerated(keyPath))
	}

	passBody := make([]byte, len(generated.passphrase)+1)
	defer clear(passBody)

	copy(passBody, generated.passphrase)

	passBody[len(passBody)-1] = '\n'

	err = disk.WriteExclusive(passPath, passBody, 0600)

	if err != nil {
		writeErr := fmt.Errorf("write OpenPGP passphrase file: %w", err)
		if errors.Is(err, os.ErrExist) {
			return nil, errors.Join(writeErr, rollbackGenerated(keyPath))
		}

		return nil, errors.Join(writeErr, rollbackGenerated(passPath, keyPath))
	}

	identity := config.OpenPGPIdentity{
		Sender:         sender,
		SigningKey:     keyRelative,
		PassphraseFile: passRelative,
		Signing:        "required",
	}

	latest.OpenPGP.Identities = append(latest.OpenPGP.Identities, identity)

	err = latest.Init()
	if err != nil {
		return nil, errors.Join(err, rollbackGenerated(passPath, keyPath))
	}

	_, err = Load(latest)
	if err != nil {
		return nil, errors.Join(fmt.Errorf("validate generated OpenPGP key: %w", err), rollbackGenerated(passPath, keyPath))
	}

	err = latest.Save()
	if err != nil {
		reloaded, reloadErr := config.LoadFile(latest.Path())
		if reloadErr != nil {
			return nil, errors.Join(err, fmt.Errorf("config commit outcome is unknown; generated key files were preserved: %w", reloadErr))
		}

		if hasConfiguredIdentity(reloaded, identity) {
			return nil, fmt.Errorf("config was replaced but durability confirmation failed; generated key files were preserved: %w", err)
		}

		return nil, errors.Join(err, rollbackGenerated(passPath, keyPath))
	}

	return &CreatedKey{
		Sender:         sender,
		Fingerprint:    generated.fingerprint,
		SigningKey:     keyRelative,
		PassphraseFile: passRelative,
	}, nil
}

func generateKey(sender string) (*generatedKey, error) {
	keyConfig := &packet.Config{
		Algorithm:     packet.PubKeyAlgoRSA,
		RSABits:       generatedRSABits,
		DefaultHash:   crypto.SHA256,
		DefaultCipher: packet.CipherAES256,
		MinRSABits:    2048,
	}

	entity, err := pgp.NewEntity("", "", sender, keyConfig)
	if err != nil {
		return nil, fmt.Errorf("generate OpenPGP key: %w", err)
	}

	passphrase := make([]byte, 32)
	defer clear(passphrase)

	_, err = rand.Read(passphrase)
	if err != nil {
		return nil, fmt.Errorf("generate OpenPGP passphrase: %w", err)
	}

	encodedPassphrase := make([]byte, hex.EncodedLen(len(passphrase)))

	hex.Encode(encodedPassphrase, passphrase)

	encryptionConfig := *keyConfig

	encryptionConfig.S2KConfig = &s2k.Config{
		S2KMode:                 s2k.SaltedS2K,
		PassphraseIsHighEntropy: true,
	}

	var keepPassphrase bool

	defer func() {
		if !keepPassphrase {
			clear(encodedPassphrase)
		}
	}()

	err = entity.EncryptPrivateKeys(encodedPassphrase, &encryptionConfig)
	if err != nil {
		return nil, fmt.Errorf("encrypt OpenPGP private key: %w", err)
	}

	var body bytes.Buffer

	armored, err := armor.Encode(&body, pgp.PrivateKeyType, nil)
	if err != nil {
		return nil, fmt.Errorf("armor OpenPGP private key: %w", err)
	}

	err = entity.SerializePrivateWithoutSigning(armored, &encryptionConfig)
	if err != nil {
		_ = armored.Close()

		return nil, fmt.Errorf("serialize OpenPGP private key: %w", err)
	}

	err = armored.Close()
	if err != nil {
		return nil, fmt.Errorf("finish OpenPGP private key armor: %w", err)
	}

	if body.Len() > maxKeyBytes {
		return nil, errors.New("generated OpenPGP private key exceeds size limit")
	}

	keepPassphrase = true

	return &generatedKey{
		armoredKey:  append([]byte(nil), body.Bytes()...),
		passphrase:  encodedPassphrase,
		fingerprint: strings.ToUpper(hex.EncodeToString(entity.PrimaryKey.Fingerprint)),
	}, nil
}

func validateCreate(cfg *config.Config, username, sender string) error {
	user, ok := cfg.User(username)
	if !ok {
		return fmt.Errorf("user %q does not exist", username)
	}

	if !user.Enabled {
		return fmt.Errorf("user %q is disabled", user.Username)
	}

	if !allowsExact(user, sender) {
		return fmt.Errorf("sender %q is not an exact allowed sender for user %q", sender, user.Username)
	}

	for _, identity := range cfg.OpenPGP.Identities {
		if identity.Sender == sender {
			return fmt.Errorf("OpenPGP identity for sender %q already exists", sender)
		}
	}

	if len(cfg.OpenPGP.Identities) >= config.MaxOpenPGPIdentities {
		return fmt.Errorf("openpgp.identities already contains the maximum of %d entries", config.MaxOpenPGPIdentities)
	}

	return nil
}

func canonicalSender(sender string) (string, error) {
	address, err := mailbox.Address(sender)
	if err != nil {
		return "", fmt.Errorf("invalid sender %q: %w", sender, err)
	}

	at := strings.LastIndexByte(address, '@')

	return address[:at] + "@" + strings.ToLower(address[at+1:]), nil
}

func allowsExact(user config.User, sender string) bool {
	at := strings.LastIndexByte(sender, '@')

	for _, allowed := range user.AllowedSenders {
		allowedAt := strings.LastIndexByte(allowed, '@')
		if allowedAt > 0 && allowed[0] != '*' && allowed[:allowedAt] == sender[:at] && strings.EqualFold(allowed[allowedAt+1:], sender[at+1:]) {
			return true
		}
	}

	return false
}

func hasConfiguredIdentity(cfg *config.Config, wanted config.OpenPGPIdentity) bool {
	for _, identity := range cfg.OpenPGP.Identities {
		if identity.Sender == wanted.Sender && identity.SigningKey == wanted.SigningKey && identity.PassphraseFile == wanted.PassphraseFile && identity.Signing == wanted.Signing {
			return true
		}
	}

	return false
}

func removeDurable(path string) error {
	err := os.Remove(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}

	return disk.Sync(filepath.Dir(path))
}

func rollbackGenerated(paths ...string) error {
	var result error

	for _, path := range paths {
		err := removeDurable(path)
		if err != nil {
			result = errors.Join(result, fmt.Errorf("remove generated file %s: %w", path, err))
		}
	}

	return result
}
