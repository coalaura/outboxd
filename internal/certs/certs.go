package certs

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"sync"
	"time"

	"github.com/coalaura/outboxd/internal/config"
	"github.com/coalaura/outboxd/internal/disk"
)

const reloadInterval = time.Minute

// Keeper serves the submission certificate and picks up renewals without a
// restart, which matters for operator-managed file rotations.
type Keeper struct {
	certificateFile string
	privateKeyFile  string
	minimumVersion  uint16
	hostname        string
	// mode is config TLS mode; self_signed is development-only (see Ensure).
	mode string

	mu          sync.Mutex
	certificate *tls.Certificate
	stamp       time.Time
	checked     time.Time
	lastError   error
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
	keeper := &Keeper{
		certificateFile: cfg.ResolvePath(cfg.TLS.CertificateFile),
		privateKeyFile:  cfg.ResolvePath(cfg.TLS.PrivateKeyFile),
		minimumVersion:  cfg.MinimumTLSVersion(),
		hostname:        cfg.Server.Hostname,
		mode:            cfg.TLS.Mode,
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
		if certOK && keyOK {
			return false, nil
		}
		// Partial pair: regenerate both. Never partial-overwrite in files mode.
		if certOK {
			if err := os.Remove(k.certificateFile); err != nil {
				return false, fmt.Errorf("remove incomplete certificate: %w", err)
			}
		}
		if keyOK {
			if err := os.Remove(k.privateKeyFile); err != nil {
				return false, fmt.Errorf("remove incomplete private key: %w", err)
			}
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
	defer k.mu.Unlock()

	if time.Since(k.checked) < reloadInterval {
		if k.certificate == nil {
			if k.lastError != nil {
				return nil, k.lastError
			}
			return nil, errors.New("no tls certificate loaded")
		}
		return k.certificate, nil
	}

	k.checked = time.Now()

	stamp, err := k.modified()
	if err != nil {
		k.lastError = err
		// Keep last valid certificate on failure.
		if k.certificate != nil {
			return k.certificate, nil
		}
		return nil, err
	}
	if !stamp.After(k.stamp) {
		return k.certificate, nil
	}

	certificate, err := k.loadPair()
	if err != nil {
		k.lastError = err
		if k.certificate != nil {
			return k.certificate, nil
		}
		return nil, err
	}

	k.certificate = certificate
	k.stamp = stamp
	k.lastError = nil
	return k.certificate, nil
}

func (k *Keeper) load() (*tls.Certificate, error) {
	certificate, err := k.loadPair()
	if err != nil {
		return nil, err
	}

	stamp, err := k.modified()
	if err != nil {
		return nil, err
	}

	k.mu.Lock()
	k.certificate = certificate
	k.stamp = stamp
	k.checked = time.Now()
	k.lastError = nil
	k.mu.Unlock()

	return certificate, nil
}

func (k *Keeper) loadPair() (*tls.Certificate, error) {
	certificate, err := tls.LoadX509KeyPair(k.certificateFile, k.privateKeyFile)
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

	if leaf.IsCA && len(certificate.Certificate) == 1 {
		// A pure CA presented as the only cert is not a usable TLS server leaf.
		// Self-signed leaves must have IsCA=false (see generate). Legacy pairs
		// with IsCA=true still work if they have ServerAuth and host match.
	}

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

func (k *Keeper) modified() (time.Time, error) {
	certificate, err := os.Stat(k.certificateFile)
	if err != nil {
		return time.Time{}, err
	}

	key, err := os.Stat(k.privateKeyFile)
	if err != nil {
		return time.Time{}, err
	}

	if key.ModTime().After(certificate.ModTime()) {
		return key.ModTime(), nil
	}

	return certificate.ModTime(), nil
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

	err = disk.WriteExclusive(k.privateKeyFile, pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: encoded,
	}), 0600)

	if err != nil {
		return err
	}

	return disk.WriteExclusive(k.certificateFile, pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: body,
	}), 0644)
}
