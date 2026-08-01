package sign

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"github.com/coalaura/outboxd/internal/config"
	"github.com/coalaura/outboxd/internal/disk"
	"github.com/emersion/go-msgauth/dkim"
)

const (
	keyBits            = 2048
	maxPrivateKeyBytes = 1 << 20
)

// Signer produces DKIM-Signature header fields for outgoing messages.
type Signer struct {
	options dkim.SignOptions

	// PublicKey is the base64 SubjectPublicKeyInfo used in the DNS record.
	PublicKey string
}

// Ensure loads the DKIM key, generating one when it does not exist yet.
func Ensure(cfg *config.Config) (*Signer, bool, error) {
	path, err := cfg.ResolveGeneratedPath(cfg.DKIM.PrivateKeyFile)
	if err != nil {
		return nil, false, err
	}

	err = cfg.CheckGeneratedParents(path)
	if err != nil {
		return nil, false, err
	}

	key, created, err := ensureKey(path)
	if err != nil {
		return nil, false, err
	}

	loaded, err := signer(cfg, key)
	if err != nil {
		return nil, false, err
	}

	return loaded, created, nil
}

// Load reads and validates the configured DKIM key without creating or
// modifying any file. Deployment checks use this read-only path.
func Load(cfg *config.Config) (*Signer, error) {
	path, err := cfg.ResolveGeneratedPath(cfg.DKIM.PrivateKeyFile)
	if err != nil {
		return nil, err
	}

	err = cfg.CheckGeneratedParents(path)
	if err != nil {
		return nil, err
	}

	key, err := loadKey(path)
	if err != nil {
		return nil, err
	}

	return signer(cfg, key)
}

func signer(cfg *config.Config, key *rsa.PrivateKey) (*Signer, error) {
	public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}

	return &Signer{
		options: dkim.SignOptions{
			Domain:                 cfg.Server.Domain,
			Selector:               cfg.DKIM.Selector,
			Signer:                 key,
			Hash:                   crypto.SHA256,
			HeaderCanonicalization: dkim.CanonicalizationRelaxed,
			BodyCanonicalization:   dkim.CanonicalizationRelaxed,
			HeaderKeys:             cfg.DKIM.Headers,
		},
		PublicKey: base64.StdEncoding.EncodeToString(public),
	}, nil
}

// Signature returns the DKIM-Signature field, including its trailing CRLF, for
// a message that is already CRLF normalized.
func (s *Signer) Signature(message []byte) (string, error) {
	signer, err := dkim.NewSigner(&s.options)
	if err != nil {
		return "", err
	}

	_, err = signer.Write(message)
	if err != nil {
		signer.Close()

		return "", err
	}

	err = signer.Close()
	if err != nil {
		return "", err
	}

	return signer.Signature(), nil
}

// Record returns the DKIM TXT record value for the generated key.
func (s *Signer) Record() string {
	return fmt.Sprintf("v=DKIM1; k=rsa; h=sha256; p=%s", s.PublicKey)
}

func ensureKey(path string) (*rsa.PrivateKey, bool, error) {
	body, err := config.ReadCheckedFile(path, true, false, maxPrivateKeyBytes)
	if err == nil {
		key, err := parseKey(body)

		return key, false, err
	}

	if !errors.Is(err, os.ErrNotExist) {
		return nil, false, err
	}

	key, err := rsa.GenerateKey(rand.Reader, keyBits)
	if err != nil {
		return nil, false, err
	}

	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, false, err
	}

	err = disk.WriteExclusive(path, pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: encoded,
	}), 0600)

	if err != nil {
		// Another process may have won the create race; adopt their key.
		if errors.Is(err, os.ErrExist) {
			body, readErr := config.ReadCheckedFile(path, true, false, maxPrivateKeyBytes)
			if readErr != nil {
				return nil, false, readErr
			}

			parsed, parseErr := parseKey(body)
			return parsed, false, parseErr
		}

		return nil, false, err
	}

	return key, true, nil
}

func loadKey(path string) (*rsa.PrivateKey, error) {
	body, err := config.ReadCheckedFile(path, true, false, maxPrivateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("read dkim private key: %w", err)
	}

	key, err := parseKey(body)
	if err != nil {
		return nil, fmt.Errorf("parse dkim private key: %w", err)
	}

	return key, nil
}

func parseKey(body []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(body)
	if block == nil {
		return nil, errors.New("dkim private key is not PEM encoded")
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}

		return validateKey(key)
	case "PRIVATE KEY":
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}

		key, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("unsupported dkim key type %T", parsed)
		}

		return validateKey(key)
	}

	return nil, fmt.Errorf("unsupported PEM block %q", block.Type)
}

func validateKey(key *rsa.PrivateKey) (*rsa.PrivateKey, error) {
	if key.N == nil || key.N.BitLen() < keyBits {
		return nil, fmt.Errorf("dkim RSA key must be at least %d bits", keyBits)
	}

	err := key.Validate()
	if err != nil {
		return nil, fmt.Errorf("invalid dkim RSA private key: %w", err)
	}

	return key, nil
}
