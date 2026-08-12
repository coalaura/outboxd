package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/coalaura/outboxd/internal/config"
	"github.com/coalaura/outboxd/internal/disk"
)

const generationMarkerText = "outboxd self-signed tls generation\n"

type generationTarget struct {
	path  string
	stage string
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
		if _, err = os.Lstat(path); err == nil {
			return fmt.Errorf("self-signed tls staging file %q already exists", path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}

	err = disk.WriteExclusive(k.generationMarker(), []byte(generationMarkerText), 0600)
	if err != nil {
		return err
	}

	err = disk.WriteExclusive(k.privateKeyStage(), keyPEM, 0600)
	if err != nil {
		return err
	}

	err = disk.WriteExclusive(k.certificateStage(), certPEM, 0644)
	if err != nil {
		return err
	}

	err = disk.Rename(k.privateKeyStage(), k.privateKeyFile)
	if err != nil {
		return err
	}

	err = disk.Rename(k.certificateStage(), k.certificateFile)
	if err != nil {
		return err
	}

	return removeDurable(k.generationMarker())
}

func (k *Keeper) generationMarker() string {
	return k.certificateFile + ".outboxd-generation"
}

func (k *Keeper) certificateStage() string {
	return k.certificateFile + ".outboxd-stage"
}

func (k *Keeper) privateKeyStage() string {
	return k.privateKeyFile + ".outboxd-stage"
}

func (k *Keeper) recoverGeneration() (bool, error) {
	targets := []generationTarget{
		{k.privateKeyFile, k.privateKeyStage()},
		{k.certificateFile, k.certificateStage()},
	}

	var (
		present   int
		available int
		finals    int
	)

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

	_, err := os.Stat(certPath)
	if errors.Is(err, os.ErrNotExist) {
		certPath = k.certificateStage()
	}

	keyPath := k.privateKeyFile

	_, err = os.Stat(keyPath)
	if errors.Is(err, os.ErrNotExist) {
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

	_, err = k.parsePair(certPEM, keyPEM)
	if err != nil {
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
				err := removeDurable(target.stage)
				if err != nil {
					return false, err
				}
			}

			continue
		}

		if stageErr == nil {
			err := disk.Rename(target.stage, target.path)
			if err != nil {
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
		err := removeIfExistsDurable(stage)
		if err != nil {
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
	err := os.Remove(path)
	if err != nil {
		return err
	}

	return disk.Sync(filepath.Dir(path))
}
