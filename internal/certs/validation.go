package certs

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"time"
)

type publicKeyEqualer interface{ Equal(crypto.PublicKey) bool }

type publicKeyer interface {
	Public() crypto.PublicKey
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
		err = matchKey(leaf, certificate.PrivateKey)
		if err != nil {
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
	err = leafHasServerAuth(leaf)
	if err != nil {
		return err
	}

	if hostname != "" {
		err = leaf.VerifyHostname(hostname)
		if err != nil {
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
	pk, ok := key.(publicKeyer)
	if !ok {
		return errors.New("tls private key type is unsupported")
	}

	pub, ok := pk.Public().(publicKeyEqualer)
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

func certificateValid(certificate *tls.Certificate, now time.Time) bool {
	if certificate == nil || len(certificate.Certificate) == 0 {
		return false
	}

	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	return err == nil && !now.Before(leaf.NotBefore) && now.Before(leaf.NotAfter)
}
