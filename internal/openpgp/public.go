package openpgp

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/mail"
	"path/filepath"
	"strings"
	"time"

	pgp "github.com/ProtonMail/go-crypto/openpgp"
	"github.com/coalaura/outboxd/internal/config"
)

const maxAutocryptFieldBytes = 10 << 10

// PublicIdentity is a minimized, transferable public key for one configured sender.
type PublicIdentity struct {
	Sender      string
	Fingerprint string
	Key         []byte
}

// LoadPublic reads configured private key files but does not decrypt or change them.
func LoadPublic(cfg *config.Config) ([]PublicIdentity, error) {
	identities := make([]PublicIdentity, 0, len(cfg.OpenPGP.Identities))

	for _, configured := range cfg.OpenPGP.Identities {
		entity, err := readEntity(cfg, configured)
		if err != nil {
			return nil, fmt.Errorf("openpgp identity %q: %w", configured.Sender, err)
		}

		identity, err := publicIdentity(entity, configured.Sender)
		if err != nil {
			return nil, fmt.Errorf("openpgp identity %q: %w", configured.Sender, err)
		}

		identities = append(identities, identity)
	}

	return identities, nil
}

func readEntity(cfg *config.Config, configured config.OpenPGPIdentity) (*pgp.Entity, error) {
	keyPath := cfg.ResolvePath(configured.SigningKey)
	if !filepath.IsAbs(configured.SigningKey) {
		err := cfg.CheckGeneratedParents(keyPath)
		if err != nil {
			return nil, fmt.Errorf("check signing key path: %w", err)
		}
	}

	keyData, err := config.ReadCheckedFile(keyPath, true, false, maxKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("read signing key: %w", err)
	}

	defer clear(keyData)

	entities, err := pgp.ReadArmoredKeyRing(bytes.NewReader(keyData))
	if err != nil {
		entities, err = pgp.ReadKeyRing(bytes.NewReader(keyData))
	}

	if err != nil {
		return nil, fmt.Errorf("parse signing key: %w", err)
	}

	if len(entities) != 1 {
		return nil, fmt.Errorf("signing key must contain exactly one entity, got %d", len(entities))
	}

	return entities[0], nil
}

func publicIdentity(entity *pgp.Entity, sender string) (PublicIdentity, error) {
	selected, err := selectIdentity(entity, sender)
	if err != nil {
		return PublicIdentity{}, err
	}

	var key bytes.Buffer

	writePacket := func(name string, serialize func(io.Writer) error) error {
		err := serialize(&key)
		if err != nil {
			return fmt.Errorf("serialize %s: %w", name, err)
		}

		return nil
	}

	err = writePacket("primary public key", entity.PrimaryKey.Serialize)
	if err != nil {
		return PublicIdentity{}, err
	}

	for _, revocation := range entity.Revocations {
		err = writePacket("primary key revocation", revocation.Serialize)
		if err != nil {
			return PublicIdentity{}, err
		}
	}

	if entity.SelfSignature != nil {
		err = writePacket("direct-key self-signature", entity.SelfSignature.Serialize)
		if err != nil {
			return PublicIdentity{}, err
		}
	}

	err = writePacket("user ID", selected.UserId.Serialize)
	if err != nil {
		return PublicIdentity{}, err
	}

	err = writePacket("user ID self-signature", selected.SelfSignature.Serialize)
	if err != nil {
		return PublicIdentity{}, err
	}

	for _, revocation := range selected.Revocations {
		err = writePacket("user ID revocation", revocation.Serialize)
		if err != nil {
			return PublicIdentity{}, err
		}
	}

	for _, subkey := range entity.Subkeys {
		if subkey.PublicKey == nil || subkey.Sig == nil {
			return PublicIdentity{}, errors.New("public subkey is missing its key or binding signature")
		}

		err = writePacket("public subkey", subkey.PublicKey.Serialize)
		if err != nil {
			return PublicIdentity{}, err
		}

		for _, revocation := range subkey.Revocations {
			err = writePacket("subkey revocation", revocation.Serialize)
			if err != nil {
				return PublicIdentity{}, err
			}
		}

		err = writePacket("subkey binding signature", subkey.Sig.Serialize)
		if err != nil {
			return PublicIdentity{}, err
		}
	}

	return PublicIdentity{
		Sender:      sender,
		Fingerprint: strings.ToUpper(hex.EncodeToString(entity.PrimaryKey.Fingerprint)),
		Key:         key.Bytes(),
	}, nil
}

func selectIdentity(entity *pgp.Entity, sender string) (*pgp.Identity, error) {
	now := time.Now()

	var selected *pgp.Identity

	for _, identity := range entity.Identities {
		if identity.UserId == nil || identity.SelfSignature == nil || identity.SelfSignature.SigExpired(now) || identity.Revoked(now) {
			continue
		}

		address, err := mail.ParseAddress(identity.Name)
		if err != nil || canonicalAddress(address.Address) != sender {
			continue
		}

		if selected != nil {
			return nil, errors.New("sender matches multiple active key identities")
		}

		selected = identity
	}

	if selected == nil {
		return nil, errors.New("sender is not present in the active key identities")
	}

	err := entity.PrimaryKey.VerifyUserIdSignature(selected.UserId.Id, entity.PrimaryKey, selected.SelfSignature)
	if err != nil {
		return nil, fmt.Errorf("verify user ID self-signature: %w", err)
	}

	return selected, nil
}

func autocryptField(identity PublicIdentity) ([]byte, error) {
	keyring, err := pgp.ReadKeyRing(bytes.NewReader(identity.Key))
	if err != nil || len(keyring) != 1 {
		return nil, errors.New("minimized public key cannot be parsed")
	}

	if _, ok := keyring[0].EncryptionKey(time.Now()); !ok {
		return nil, errors.New("Autocrypt requires a currently valid encryption key")
	}

	encoded := base64.StdEncoding.EncodeToString(identity.Key)

	prefix := "Autocrypt: addr=" + identity.Sender + "; keydata="

	var field strings.Builder
	field.Grow(len(prefix) + len(encoded) + len(encoded)/76*3 + 2)

	field.WriteString(prefix)

	for start := 0; start < len(encoded); start += 76 {
		if start > 0 {
			field.WriteString("\r\n ")
		}

		field.WriteString(encoded[start:min(start+76, len(encoded))])
	}

	field.WriteString("\r\n")
	if field.Len() > maxAutocryptFieldBytes {
		return nil, fmt.Errorf("Autocrypt field is %d bytes; maximum is %d", field.Len(), maxAutocryptFieldBytes)
	}

	return []byte(field.String()), nil
}
