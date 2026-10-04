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
	"strings"

	"github.com/coalaura/outboxd/internal/config"
	"github.com/coalaura/outboxd/internal/disk"
	"github.com/coalaura/outboxd/internal/mailbox"
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

// Signers holds immutable, independently provisioned domain identities.
type Signers struct {
	domains map[string]*Signer
}

// Signature signs with the most specific configured domain covering From.
// The caller supplies the validated From mailbox, never the envelope sender.
func (s *Signers) Signature(from string, message []byte) (string, error) {
	domain, err := mailbox.DomainOf(from)
	if err != nil {
		return "", err
	}

	for domain != "" {
		if signer, exists := s.domains[domain]; exists {
			return signer.Signature(message)
		}

		_, domain, _ = strings.Cut(domain, ".")
	}

	return "", fmt.Errorf("no DKIM identity for From %q", from)
}

// PublicKeys returns the public key for each exact configured domain.
func (s *Signers) PublicKeys() map[string]string {
	keys := make(map[string]string, len(s.domains))

	for domain, signer := range s.domains {
		keys[domain] = signer.PublicKey
	}

	return keys
}

// Records returns the DKIM TXT value for each exact configured domain.
func (s *Signers) Records() map[string]string {
	records := make(map[string]string, len(s.domains))

	for domain, signer := range s.domains {
		records[domain] = signer.Record()
	}

	return records
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

// Ensure explicitly provisions missing DKIM keys without replacing existing ones.
// The boolean reports whether any key was created. Operational paths use Load.
func Ensure(cfg *config.Config) (*Signers, bool, error) {
	return load(cfg, true)
}

// Load reads every configured DKIM key without modifying the filesystem.
func Load(cfg *config.Config) (*Signers, error) {
	signers, _, err := load(cfg, false)

	return signers, err
}

func load(cfg *config.Config, provision bool) (*Signers, bool, error) {
	signers := &Signers{domains: make(map[string]*Signer, len(cfg.Domains))}

	publicKeys := make(map[string]string, len(cfg.Domains))

	var generated bool

	for i := range cfg.Domains {
		domain := &cfg.Domains[i]

		path, err := cfg.ResolveGeneratedPath(domain.DKIM.PrivateKeyFile)
		if err != nil {
			return nil, generated, fmt.Errorf("DKIM %s: %w", domain.Name, err)
		}

		err = cfg.CheckGeneratedParents(path)
		if err != nil {
			return nil, generated, fmt.Errorf("DKIM %s: %w", domain.Name, err)
		}

		var key *rsa.PrivateKey

		if provision {
			var created bool

			key, created, err = ensureKey(path)
			generated = generated || created
		} else {
			key, err = loadKey(path)
		}

		if err != nil {
			return nil, generated, fmt.Errorf("DKIM %s: %w", domain.Name, err)
		}

		loaded, err := signer(domain, key)
		if err != nil {
			return nil, generated, fmt.Errorf("DKIM %s: %w", domain.Name, err)
		}

		if previous, exists := publicKeys[loaded.PublicKey]; exists {
			return nil, generated, fmt.Errorf("DKIM domains %s and %s must use distinct keys", previous, domain.Name)
		}

		publicKeys[loaded.PublicKey] = domain.Name
		signers.domains[domain.Name] = loaded
	}

	return signers, generated, nil
}

func signer(domain *config.Domain, key *rsa.PrivateKey) (*Signer, error) {
	public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}

	return &Signer{
		options: dkim.SignOptions{
			Domain:                 domain.Name,
			Selector:               domain.DKIM.Selector,
			Signer:                 key,
			Hash:                   crypto.SHA256,
			HeaderCanonicalization: dkim.CanonicalizationRelaxed,
			BodyCanonicalization:   dkim.CanonicalizationRelaxed,
			HeaderKeys:             domain.DKIM.Headers,
		},
		PublicKey: base64.StdEncoding.EncodeToString(public),
	}, nil
}

func ensureKey(path string) (*rsa.PrivateKey, bool, error) {
	body, err := config.ReadCheckedFile(path, true, false, maxPrivateKeyBytes)
	if err == nil {
		defer clear(body)

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

	defer clear(encoded)

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: encoded,
	})

	defer clear(keyPEM)

	err = disk.WriteExclusive(path, keyPEM, 0600)
	if err != nil {
		// Another process may have won the create race; adopt their key.
		if errors.Is(err, os.ErrExist) {
			body, readErr := config.ReadCheckedFile(path, true, false, maxPrivateKeyBytes)
			if readErr != nil {
				return nil, false, readErr
			}

			defer clear(body)

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

	defer clear(body)

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
