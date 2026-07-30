package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/coalaura/outboxd/internal/disk"
)

func ensureWithDir(t *testing.T, dir, mode string) (*Keeper, bool, error) {
	t.Helper()
	k := &Keeper{
		certificateFile: filepath.Join(dir, "server.crt"),
		privateKeyFile:  filepath.Join(dir, "server.key"),
		minimumVersion:  0x0303,
		hostname:        "mail.test.example",
		mode:            mode,
	}
	created, err := k.ensureFiles()
	if err != nil {
		return nil, false, err
	}
	if _, err := k.load(); err != nil {
		return nil, false, err
	}
	return k, created, nil
}

func TestSelfSignedLeafNotCA(t *testing.T) {
	dir := t.TempDir()
	k, created, err := ensureWithDir(t, dir, "self_signed")
	if err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Fatal("expected created")
	}
	leaf, err := x509.ParseCertificate(k.certificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if leaf.IsCA {
		t.Fatal("self-signed leaf must have IsCA=false")
	}
	if leaf.KeyUsage&x509.KeyUsageCertSign != 0 {
		t.Fatal("must not have CertSign")
	}
	if leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Fatal("must have DigitalSignature")
	}
	found := false
	for _, u := range leaf.ExtKeyUsage {
		if u == x509.ExtKeyUsageServerAuth {
			found = true
		}
	}
	if !found {
		t.Fatal("missing ServerAuth EKU")
	}
	if err := leaf.VerifyHostname("mail.test.example"); err != nil {
		t.Fatal(err)
	}
}

func TestPartialPairRecoverySelfSigned(t *testing.T) {
	dir := t.TempDir()
	// Create only a key file initially.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "server.key")
	if err := disk.WriteExclusive(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: enc}), 0600); err != nil {
		t.Fatal(err)
	}

	k, created, err := ensureWithDir(t, dir, "self_signed")
	if err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Fatal("expected regeneration")
	}
	if _, err := os.Stat(filepath.Join(dir, "server.crt")); err != nil {
		t.Fatal("cert missing after recovery")
	}
	if k.certificate == nil {
		t.Fatal("no certificate loaded")
	}
}

func TestFilesModeDoesNotOverwritePartial(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "server.key")
	if err := os.WriteFile(keyPath, []byte("not-a-real-key"), 0600); err != nil {
		t.Fatal(err)
	}
	_, _, err := ensureWithDir(t, dir, "files")
	if err == nil {
		t.Fatal("expected error when cert missing in files mode")
	}
	// Key must remain untouched content-wise.
	body, _ := os.ReadFile(keyPath)
	if string(body) != "not-a-real-key" {
		t.Fatal("files mode overwrote user key")
	}
}

func TestValidateRejectsHostnameMismatch(t *testing.T) {
	dir := t.TempDir()
	if err := writeSelfSigned(dir, "other.example"); err != nil {
		t.Fatal(err)
	}
	k := &Keeper{
		certificateFile: filepath.Join(dir, "server.crt"),
		privateKeyFile:  filepath.Join(dir, "server.key"),
		hostname:        "mail.test.example",
		mode:            "files",
	}
	if _, err := k.load(); err == nil {
		t.Fatal("expected hostname mismatch error")
	}
}

func TestHotReloadKeepsLastValid(t *testing.T) {
	dir := t.TempDir()
	k, _, err := ensureWithDir(t, dir, "self_signed")
	if err != nil {
		t.Fatal(err)
	}
	// Force reload window open.
	k.mu.Lock()
	k.checked = time.Time{}
	good := k.certificate
	k.mu.Unlock()

	// Corrupt the cert file.
	if err := os.WriteFile(filepath.Join(dir, "server.crt"), []byte("broken"), 0644); err != nil {
		t.Fatal(err)
	}
	// Touch mtime so modified() sees a change.
	future := time.Now().Add(time.Second)
	_ = os.Chtimes(filepath.Join(dir, "server.crt"), future, future)
	_ = os.Chtimes(filepath.Join(dir, "server.key"), future, future)

	k.mu.Lock()
	k.checked = time.Time{}
	k.mu.Unlock()

	cert, err := k.get(nil)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if cert != good {
		// pointer may differ if copy — compare leaf serial
		if len(cert.Certificate) == 0 || len(good.Certificate) == 0 {
			t.Fatal("missing cert material")
		}
		a, _ := x509.ParseCertificate(cert.Certificate[0])
		b, _ := x509.ParseCertificate(good.Certificate[0])
		if a.SerialNumber.Cmp(b.SerialNumber) != 0 {
			t.Fatal("did not keep last valid certificate")
		}
	}
	if k.LastError() == nil {
		t.Fatal("expected LastError after failed reload")
	}
	st := k.Status()
	if !st.Loaded {
		t.Fatal("status should still show loaded previous cert")
	}
}

func TestConfigHasNoCipherSuites(t *testing.T) {
	dir := t.TempDir()
	k, _, err := ensureWithDir(t, dir, "self_signed")
	if err != nil {
		t.Fatal(err)
	}
	tc := k.Config()
	if len(tc.CipherSuites) != 0 {
		t.Fatalf("CipherSuites should be empty (Go defaults), got %v", tc.CipherSuites)
	}
	if tc.MinVersion == 0 {
		t.Fatal("MinVersion should be set")
	}
}

func writeSelfSigned(dir, hostname string) error {
	k := &Keeper{
		certificateFile: filepath.Join(dir, "server.crt"),
		privateKeyFile:  filepath.Join(dir, "server.key"),
		hostname:        hostname,
		mode:            "self_signed",
	}
	return k.generate(hostname)
}

func TestGenerateTemplateFields(t *testing.T) {
	// Direct unit of generate via ensure.
	dir := t.TempDir()
	k := &Keeper{
		certificateFile: filepath.Join(dir, "c.crt"),
		privateKeyFile:  filepath.Join(dir, "c.key"),
	}
	if err := k.generate("hn.example"); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(k.certificateFile)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(body)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if cert.IsCA {
		t.Fatal("IsCA")
	}
	if cert.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Fatalf("KeyUsage=%v", cert.KeyUsage)
	}
	// Expired mount: NotAfter far future, NotBefore ok
	if time.Now().After(cert.NotAfter) {
		t.Fatal("already expired")
	}
}
