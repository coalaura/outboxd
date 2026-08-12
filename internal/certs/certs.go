package certs

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/coalaura/outboxd/internal/config"
)

const (
	reloadInterval      = time.Minute
	maxCertificateBytes = 4 << 20
	maxPrivateKeyBytes  = 1 << 20
)

// Keeper serves the submission certificate and picks up renewals without a
// restart, which matters for operator-managed file rotations.
type Keeper struct {
	certificateFile string
	privateKeyFile  string
	minimumVersion  uint16
	hostname        string
	mode            string

	mu            sync.Mutex
	certificate   *tls.Certificate
	fingerprint   [sha256.Size]byte
	checked       time.Time
	lastError     error
	onReloadError func(error)
}

// Status is a snapshot of the loaded certificate for observability.
type Status struct {
	Loaded    bool
	NotBefore time.Time
	NotAfter  time.Time
	DNSNames  []string
	LastError string
}

func (k *Keeper) ensureFiles() (bool, error) {
	_, certErr := os.Stat(k.certificateFile)
	_, keyErr := os.Stat(k.privateKeyFile)

	certOK := certErr == nil
	keyOK := keyErr == nil

	if certErr != nil && !errors.Is(certErr, os.ErrNotExist) {
		return false, certErr
	}

	if keyErr != nil && !errors.Is(keyErr, os.ErrNotExist) {
		return false, keyErr
	}

	// tls.mode=self_signed is development-only (untrusted leaf for local clients).
	if k.mode == "self_signed" {
		_, err := os.Stat(k.generationMarker())
		if err == nil {
			complete, err := k.recoverGeneration()
			if err != nil {
				return false, err
			}

			if complete {
				return true, nil
			}

			return true, k.generate(k.hostname)
		} else if !errors.Is(err, os.ErrNotExist) {
			return false, err
		}

		if certOK && keyOK {
			return false, nil
		}

		if certOK || keyOK {
			return false, fmt.Errorf("incomplete self-signed tls pair: certificate exists=%t, private key exists=%t; refusing to replace configured files", certOK, keyOK)
		}

		err = k.generate(k.hostname)
		if err != nil {
			return false, err
		}

		return true, nil
	}

	if !certOK {
		return false, fmt.Errorf("tls certificate %q does not exist", k.certificateFile)
	}

	if !keyOK {
		return false, fmt.Errorf("tls private key %q does not exist", k.privateKeyFile)
	}

	return false, nil
}

// Config returns the TLS configuration for both submission listeners.
// Cipher suite selection is left to the Go defaults for the MinVersion floor.
func (k *Keeper) Config() *tls.Config {
	return &tls.Config{
		MinVersion:     k.minimumVersion,
		GetCertificate: k.get,
	}
}

// LastError returns the most recent reload or validation error, if any.
func (k *Keeper) LastError() error {
	k.mu.Lock()
	defer k.mu.Unlock()

	return k.lastError
}

// SetReloadErrorHandler installs an observability callback for failed reloads.
// Reload checks are already rate-limited by reloadInterval.
func (k *Keeper) SetReloadErrorHandler(handler func(error)) {
	k.mu.Lock()
	k.onReloadError = handler
	k.mu.Unlock()
}

// Status returns observability details for the currently served certificate.
func (k *Keeper) Status() Status {
	k.mu.Lock()
	defer k.mu.Unlock()

	st := Status{}

	if k.lastError != nil {
		st.LastError = k.lastError.Error()
	}

	if k.certificate == nil || len(k.certificate.Certificate) == 0 {
		return st
	}

	leaf, err := x509.ParseCertificate(k.certificate.Certificate[0])
	if err != nil {
		st.LastError = err.Error()

		return st
	}

	st.Loaded = true
	st.NotBefore = leaf.NotBefore
	st.NotAfter = leaf.NotAfter
	st.DNSNames = append([]string{}, leaf.DNSNames...)

	return st
}

func (k *Keeper) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	k.mu.Lock()

	if time.Since(k.checked) < reloadInterval {
		certificate, lastError := k.certificate, k.lastError
		k.mu.Unlock()

		if !certificateValid(certificate, time.Now()) {
			if lastError != nil {
				return nil, lastError
			}

			return nil, errors.New("no currently valid tls certificate loaded")
		}

		return certificate, nil
	}

	k.checked = time.Now()
	oldCertificate, oldFingerprint := k.certificate, k.fingerprint
	k.mu.Unlock()

	certPEM, keyPEM, fingerprint, err := k.readPair()
	if err != nil {
		return k.finishReloadError(oldCertificate, err)
	}

	if fingerprint == oldFingerprint {
		if !certificateValid(oldCertificate, time.Now()) {
			err := errors.New("loaded tls certificate is no longer valid")

			return k.finishReloadError(oldCertificate, err)
		}

		k.mu.Lock()
		k.lastError = nil
		k.mu.Unlock()

		return oldCertificate, nil
	}

	certificate, err := k.parsePair(certPEM, keyPEM)
	if err != nil {
		return k.finishReloadError(oldCertificate, err)
	}

	k.mu.Lock()
	k.certificate = certificate
	k.fingerprint = fingerprint
	k.lastError = nil
	k.mu.Unlock()

	return certificate, nil
}

func (k *Keeper) load() (*tls.Certificate, error) {
	certificate, fingerprint, err := k.loadPair()
	if err != nil {
		return nil, err
	}

	k.mu.Lock()
	k.certificate = certificate
	k.fingerprint = fingerprint
	k.checked = time.Now()
	k.lastError = nil
	k.mu.Unlock()

	return certificate, nil
}

func (k *Keeper) loadPair() (*tls.Certificate, [sha256.Size]byte, error) {
	certPEM, keyPEM, fingerprint, err := k.readPair()
	if err != nil {
		return nil, fingerprint, err
	}

	certificate, err := k.parsePair(certPEM, keyPEM)
	if err != nil {
		return nil, fingerprint, err
	}

	return certificate, fingerprint, nil
}

func (k *Keeper) parsePair(certPEM, keyPEM []byte) (*tls.Certificate, error) {
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}

	err = validateCertificate(&certificate, k.hostname)
	if err != nil {
		return nil, err
	}

	return &certificate, nil
}

func (k *Keeper) readPair() ([]byte, []byte, [sha256.Size]byte, error) {
	var fingerprint [sha256.Size]byte

	allowSymlink := k.mode == "files"

	certPEM, err := config.ReadCheckedFile(k.certificateFile, false, allowSymlink, maxCertificateBytes)
	if err != nil {
		return nil, nil, fingerprint, fmt.Errorf("tls certificate: %w", err)
	}

	keyPEM, err := config.ReadCheckedFile(k.privateKeyFile, true, allowSymlink, maxPrivateKeyBytes)
	if err != nil {
		return nil, nil, fingerprint, fmt.Errorf("tls private key: %w", err)
	}

	h := sha256.New()

	_, _ = h.Write(certPEM)
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(keyPEM)

	copy(fingerprint[:], h.Sum(nil))

	return certPEM, keyPEM, fingerprint, nil
}

func (k *Keeper) finishReloadError(certificate *tls.Certificate, err error) (*tls.Certificate, error) {
	k.mu.Lock()
	k.lastError = err
	handler := k.onReloadError
	k.mu.Unlock()

	if handler != nil {
		handler(err)
	}

	if certificateValid(certificate, time.Now()) {
		return certificate, nil
	}

	return nil, err
}

// Ensure loads the submission certificate, generating a self-signed pair when
// tls.mode is self_signed and no usable pair exists yet.
//
// self_signed is development-only: ordinary SMTP clients will not trust the
// certificate. Production must use tls.mode=files with a publicly trusted leaf.
func Ensure(cfg *config.Config) (*Keeper, bool, error) {
	keeper, err := configuredKeeper(cfg)
	if err != nil {
		return nil, false, err
	}

	created, err := keeper.ensureFiles()
	if err != nil {
		return nil, false, err
	}

	_, err = keeper.load()
	if err != nil {
		return nil, false, err
	}

	return keeper, created, nil
}

// Load reads and validates the serving certificate without creating or
// modifying files. Deployment checks use this read-only path.
func Load(cfg *config.Config) (*Keeper, error) {
	keeper, err := configuredKeeper(cfg)
	if err != nil {
		return nil, err
	}

	_, err = keeper.load()
	if err != nil {
		return nil, err
	}

	return keeper, nil
}

// Check validates the configured serving certificate without modifying files.
func Check(cfg *config.Config) error {
	return CheckWithRoots(cfg, nil)
}

// CheckWithRoots verifies the configured serving chain. A nil pool uses the
// operating system roots; tests can provide a deterministic trust store.
func CheckWithRoots(cfg *config.Config, roots *x509.CertPool) error {
	keeper, err := Load(cfg)
	if err != nil {
		return err
	}

	keeper.mu.Lock()
	certificate := keeper.certificate
	keeper.mu.Unlock()

	return verifyChain(certificate, keeper.hostname, roots, time.Now())
}

func configuredKeeper(cfg *config.Config) (*Keeper, error) {
	certificateFile := cfg.ResolvePath(cfg.TLS.CertificateFile)
	privateKeyFile := cfg.ResolvePath(cfg.TLS.PrivateKeyFile)

	if cfg.TLS.Mode == "self_signed" {
		var err error

		certificateFile, err = cfg.ResolveGeneratedPath(cfg.TLS.CertificateFile)
		if err != nil {
			return nil, fmt.Errorf("tls certificate file: %w", err)
		}

		privateKeyFile, err = cfg.ResolveGeneratedPath(cfg.TLS.PrivateKeyFile)
		if err != nil {
			return nil, fmt.Errorf("tls private key file: %w", err)
		}

		err = cfg.CheckGeneratedParents(certificateFile)
		if err != nil {
			return nil, fmt.Errorf("tls certificate file: %w", err)
		}

		err = cfg.CheckGeneratedParents(privateKeyFile)
		if err != nil {
			return nil, fmt.Errorf("tls private key file: %w", err)
		}
	}

	return &Keeper{
		certificateFile: certificateFile,
		privateKeyFile:  privateKeyFile,
		minimumVersion:  cfg.MinimumTLSVersion(),
		hostname:        cfg.Server.Hostname,
		mode:            cfg.TLS.Mode,
	}, nil
}
