package certs

import (
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
// restart, which matters for ACME managed files.
type Keeper struct {
	certificateFile string
	privateKeyFile  string
	minimumVersion  uint16

	mu          sync.Mutex
	certificate *tls.Certificate
	stamp       time.Time
	checked     time.Time
}

// Ensure loads the submission certificate, generating a self-signed pair when
// tls.mode is self_signed and no files exist yet.
func Ensure(cfg *config.Config) (*Keeper, bool, error) {
	keeper := &Keeper{
		certificateFile: cfg.ResolvePath(cfg.TLS.CertificateFile),
		privateKeyFile:  cfg.ResolvePath(cfg.TLS.PrivateKeyFile),
		minimumVersion:  cfg.MinimumTLSVersion(),
	}

	var created bool

	_, err := os.Stat(keeper.certificateFile)
	if errors.Is(err, os.ErrNotExist) {
		if cfg.TLS.Mode != "self_signed" {
			return nil, false, fmt.Errorf("tls certificate %q does not exist", keeper.certificateFile)
		}

		err = keeper.generate(cfg.Server.Hostname)
		if err != nil {
			return nil, false, err
		}

		created = true
	} else if err != nil {
		return nil, false, err
	}

	_, err = keeper.load()
	if err != nil {
		return nil, false, err
	}

	return keeper, created, nil
}

// Config returns the TLS configuration for both submission listeners.
func (k *Keeper) Config() *tls.Config {
	return &tls.Config{
		MinVersion:     k.minimumVersion,
		GetCertificate: k.get,
		// AEAD only; the CBC suites Go still allows for TLS 1.2 cost points on every serious TLS scanner.
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
	}
}

func (k *Keeper) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	if time.Since(k.checked) < reloadInterval {
		return k.certificate, nil
	}

	k.checked = time.Now()

	stamp, err := k.modified()
	if err != nil || !stamp.After(k.stamp) {
		return k.certificate, nil
	}

	certificate, err := tls.LoadX509KeyPair(k.certificateFile, k.privateKeyFile)
	if err != nil {
		return k.certificate, nil
	}

	k.certificate = &certificate
	k.stamp = stamp

	return k.certificate, nil
}

func (k *Keeper) load() (*tls.Certificate, error) {
	certificate, err := tls.LoadX509KeyPair(k.certificateFile, k.privateKeyFile)
	if err != nil {
		return nil, err
	}

	stamp, err := k.modified()
	if err != nil {
		return nil, err
	}

	k.mu.Lock()
	k.certificate = &certificate
	k.stamp = stamp
	k.checked = time.Now()
	k.mu.Unlock()

	return &certificate, nil
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

	template := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: hostname},
		DNSNames:              []string{hostname},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
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
