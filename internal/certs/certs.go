package certs

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/coalaura/outboxd/internal/config"
	"github.com/coalaura/outboxd/internal/disk"
)

const (
	reloadInterval       = time.Minute
	maxCertificateBytes  = 4 << 20
	maxPrivateKeyBytes   = 1 << 20
	generationMarkerText = "outboxd self-signed tls generation\n"
)

// Keeper serves the submission certificate and picks up renewals without a
// restart, which matters for operator-managed file rotations.
type Keeper struct {
	certificateFile string
	privateKeyFile  string
	minimumVersion  uint16
	hostname        string
	// mode is config TLS mode; self_signed is development-only (see Ensure).
	mode string

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
	if _, err := keeper.load(); err != nil {
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
		if err := cfg.CheckGeneratedParents(certificateFile); err != nil {
			return nil, fmt.Errorf("tls certificate file: %w", err)
		}
		if err := cfg.CheckGeneratedParents(privateKeyFile); err != nil {
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
		if _, err := os.Stat(k.generationMarker()); err == nil {
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
		if err := k.generate(k.hostname); err != nil {
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

	if err := validateCertificate(&certificate, k.hostname); err != nil {
		return nil, err
	}
	return &certificate, nil
}

func validateCertificate(certificate *tls.Certificate, hostname string) error {
	if len(certificate.Certificate) == 0 {
		return errors.New("tls certificate chain is empty")
	}

	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return fmt.Errorf("parse leaf certificate: %w", err)
	}

	// Ensure private key matches the leaf (LoadX509KeyPair already checks, re-assert).
	if certificate.PrivateKey != nil {
		if err := matchKey(leaf, certificate.PrivateKey); err != nil {
			return err
		}
	}

	now := time.Now()
	if now.Before(leaf.NotBefore) {
		return fmt.Errorf("tls certificate not yet valid (NotBefore %s)", leaf.NotBefore.Format(time.RFC3339))
	}
	if now.After(leaf.NotAfter) {
		return fmt.Errorf("tls certificate expired (NotAfter %s)", leaf.NotAfter.Format(time.RFC3339))
	}

	// A pure CA presented as the only cert is not a usable TLS server leaf.
	// Self-signed leaves must have IsCA=false (see generate). Legacy pairs
	// with IsCA=true still work if they have ServerAuth and host match.
	if err := leafHasServerAuth(leaf); err != nil {
		return err
	}

	if hostname != "" {
		if err := leaf.VerifyHostname(hostname); err != nil {
			return fmt.Errorf("tls certificate does not match hostname %q: %w", hostname, err)
		}
	}

	return nil
}

func verifyChain(certificate *tls.Certificate, hostname string, roots *x509.CertPool, now time.Time) error {
	if certificate == nil || len(certificate.Certificate) == 0 {
		return errors.New("tls certificate chain is empty")
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return fmt.Errorf("parse leaf certificate: %w", err)
	}
	intermediates := x509.NewCertPool()
	for _, raw := range certificate.Certificate[1:] {
		intermediate, err := x509.ParseCertificate(raw)
		if err != nil {
			return fmt.Errorf("parse intermediate certificate: %w", err)
		}
		intermediates.AddCert(intermediate)
	}
	_, err = leaf.Verify(x509.VerifyOptions{
		DNSName:       hostname,
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		CurrentTime:   now,
	})
	if err != nil {
		return fmt.Errorf("verify tls certificate chain: %w", err)
	}
	return nil
}

func matchKey(leaf *x509.Certificate, key any) error {
	type publicKeyer interface {
		Public() crypto.PublicKey
	}
	pk, ok := key.(publicKeyer)
	if !ok {
		return errors.New("tls private key type is unsupported")
	}
	pub, ok := pk.Public().(interface{ Equal(crypto.PublicKey) bool })
	if !ok {
		// Fall back: compare raw SPKI encodings.
		want, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
		if err != nil {
			return err
		}
		got, err := x509.MarshalPKIXPublicKey(pk.Public())
		if err != nil {
			return err
		}
		if string(want) != string(got) {
			return errors.New("tls private key does not match certificate")
		}
		return nil
	}
	if !pub.Equal(leaf.PublicKey) {
		return errors.New("tls private key does not match certificate")
	}
	return nil
}

func leafHasServerAuth(leaf *x509.Certificate) error {
	if len(leaf.ExtKeyUsage) == 0 && len(leaf.UnknownExtKeyUsage) == 0 {
		// Absent EKU means unrestricted; acceptable for many CA-minted leaves.
		return nil
	}
	for _, u := range leaf.ExtKeyUsage {
		if u == x509.ExtKeyUsageServerAuth || u == x509.ExtKeyUsageAny {
			return nil
		}
	}
	return errors.New("tls certificate lacks serverAuth extended key usage")
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

func certificateValid(certificate *tls.Certificate, now time.Time) bool {
	if certificate == nil || len(certificate.Certificate) == 0 {
		return false
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	return err == nil && !now.Before(leaf.NotBefore) && now.Before(leaf.NotAfter)
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

func (k *Keeper) generate(hostname string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}

	now := time.Now()

	// Leaf only: not a CA. DigitalSignature for TLS, ServerAuth EKU.
	template := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: hostname},
		DNSNames:              []string{hostname},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	body, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return err
	}

	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: encoded,
	})
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: body,
	})

	for _, path := range []string{k.privateKeyStage(), k.certificateStage()} {
		if _, err := os.Lstat(path); err == nil {
			return fmt.Errorf("self-signed tls staging file %q already exists", path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if err := disk.WriteExclusive(k.generationMarker(), []byte(generationMarkerText), 0600); err != nil {
		return err
	}
	if err := disk.WriteExclusive(k.privateKeyStage(), keyPEM, 0600); err != nil {
		return err
	}
	if err := disk.WriteExclusive(k.certificateStage(), certPEM, 0644); err != nil {
		return err
	}
	if err := disk.Rename(k.privateKeyStage(), k.privateKeyFile); err != nil {
		return err
	}
	if err := disk.Rename(k.certificateStage(), k.certificateFile); err != nil {
		return err
	}
	return removeDurable(k.generationMarker())
}

func (k *Keeper) generationMarker() string { return k.certificateFile + ".outboxd-generation" }
func (k *Keeper) certificateStage() string { return k.certificateFile + ".outboxd-stage" }
func (k *Keeper) privateKeyStage() string  { return k.privateKeyFile + ".outboxd-stage" }

func (k *Keeper) recoverGeneration() (bool, error) {
	targets := []struct {
		path  string
		stage string
	}{
		{k.privateKeyFile, k.privateKeyStage()},
		{k.certificateFile, k.certificateStage()},
	}
	present := 0
	available := 0
	finals := 0
	for _, target := range targets {
		_, targetErr := os.Stat(target.path)
		_, stageErr := os.Stat(target.stage)
		if targetErr == nil || stageErr == nil {
			available++
		}
		if targetErr == nil {
			finals++
		}
		if targetErr != nil && !errors.Is(targetErr, os.ErrNotExist) {
			return false, targetErr
		}
		if stageErr != nil && !errors.Is(stageErr, os.ErrNotExist) {
			return false, stageErr
		}
	}
	if available != len(targets) {
		if finals != 0 {
			return false, errors.New("incomplete marked self-signed tls generation cannot be recovered without replacing a final file")
		}
		return false, k.discardGenerationStages()
	}
	certPath := k.certificateFile
	if _, err := os.Stat(certPath); errors.Is(err, os.ErrNotExist) {
		certPath = k.certificateStage()
	}
	keyPath := k.privateKeyFile
	if _, err := os.Stat(keyPath); errors.Is(err, os.ErrNotExist) {
		keyPath = k.privateKeyStage()
	}
	certPEM, certErr := config.ReadCheckedFile(certPath, false, false, maxCertificateBytes)
	keyPEM, keyErr := config.ReadCheckedFile(keyPath, true, false, maxPrivateKeyBytes)
	if certErr != nil || keyErr != nil {
		if finals == 0 {
			return false, k.discardGenerationStages()
		}
		return false, fmt.Errorf("validate interrupted self-signed generation: %w", errors.Join(certErr, keyErr))
	}
	if _, err := k.parsePair(certPEM, keyPEM); err != nil {
		if finals == 0 {
			return false, k.discardGenerationStages()
		}
		return false, fmt.Errorf("validate interrupted self-signed generation: %w", err)
	}
	for _, target := range targets {
		_, targetErr := os.Stat(target.path)
		_, stageErr := os.Stat(target.stage)
		if targetErr == nil {
			present++
			if stageErr == nil {
				if err := removeDurable(target.stage); err != nil {
					return false, err
				}
			}
			continue
		}
		if stageErr == nil {
			if err := disk.Rename(target.stage, target.path); err != nil {
				return false, err
			}
			present++
		}
	}
	if present == len(targets) {
		return true, removeDurable(k.generationMarker())
	}
	return false, errors.New("incomplete marked self-signed tls generation cannot be recovered")
}

func (k *Keeper) discardGenerationStages() error {
	for _, stage := range []string{k.privateKeyStage(), k.certificateStage()} {
		if err := removeIfExistsDurable(stage); err != nil {
			return err
		}
	}
	return removeDurable(k.generationMarker())
}

func removeIfExistsDurable(path string) error {
	err := removeDurable(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func removeDurable(path string) error {
	if err := os.Remove(path); err != nil {
		return err
	}
	return disk.Sync(filepath.Dir(path))
}
