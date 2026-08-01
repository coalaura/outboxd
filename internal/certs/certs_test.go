package certs

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coalaura/outboxd/internal/config"
)

type servingCertificateCase struct {
	name string
	prep func(t *testing.T, dir string)
	want string
}

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

	_, err = k.load()
	if err != nil {
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

	err = leaf.VerifyHostname("mail.test.example")
	if err != nil {
		t.Fatal(err)
	}
}

func TestPartialPairSelfSignedPreservesConfiguredFile(t *testing.T) {
	for _, name := range []string{"server.crt", "server.key"} {

		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, name)
			body := []byte("operator bytes must remain")
			mode := os.FileMode(0644)
			if name == "server.key" {
				mode = 0600
			}

			err := os.WriteFile(path, body, mode)
			if err != nil {
				t.Fatal(err)
			}

			_, created, err := ensureWithDir(t, dir, "self_signed")
			if err == nil || !strings.Contains(err.Error(), "incomplete self-signed tls pair") {
				t.Fatalf("partial pair error=%v", err)
			}

			if created {
				t.Fatal("partial pair reported generation")
			}

			got, readErr := os.ReadFile(path)
			if readErr != nil || string(got) != string(body) {
				t.Fatalf("configured file changed: body=%q err=%v", got, readErr)
			}

			other := "server.crt"
			if name == other {
				other = "server.key"
			}

			_, statErr := os.Stat(filepath.Join(dir, other))
			if !os.IsNotExist(statErr) {
				t.Fatalf("missing half was generated: %v", statErr)
			}
		})
	}
}

func TestSelfSignedGenerationRecoversMarkedPartialPair(t *testing.T) {
	source := t.TempDir()
	err := writeSelfSigned(source, "mail.test.example")
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	k := &Keeper{
		certificateFile: filepath.Join(dir, "server.crt"),
		privateKeyFile:  filepath.Join(dir, "server.key"),
		hostname:        "mail.test.example",
		mode:            "self_signed",
	}
	key, err := os.ReadFile(filepath.Join(source, "server.key"))
	if err != nil {
		t.Fatal(err)
	}

	cert, err := os.ReadFile(filepath.Join(source, "server.crt"))
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile(k.generationMarker(), []byte(generationMarkerText), 0600)
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile(k.privateKeyFile, key, 0600)
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile(k.certificateStage(), cert, 0644)
	if err != nil {
		t.Fatal(err)
	}

	loaded, created, err := ensureWithDir(t, dir, "self_signed")
	if err != nil {
		t.Fatal(err)
	}

	if !created || loaded.certificate == nil {
		t.Fatal("marked partial generation was not recovered")
	}

	for _, path := range []string{k.generationMarker(), k.certificateStage(), k.privateKeyStage()} {

		_, err = os.Stat(path)
		if !os.IsNotExist(err) {
			t.Fatalf("generation artifact remains at %s: %v", path, err)
		}
	}
}

func TestSelfSignedGenerationRecoversMarkerWithSingleStage(t *testing.T) {
	dir := t.TempDir()
	k := &Keeper{
		certificateFile: filepath.Join(dir, "server.crt"),
		privateKeyFile:  filepath.Join(dir, "server.key"),
		hostname:        "mail.test.example",
		mode:            "self_signed",
	}
	err := os.WriteFile(k.generationMarker(), []byte(generationMarkerText), 0600)
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile(k.privateKeyStage(), []byte("interrupted key stage"), 0600)
	if err != nil {
		t.Fatal(err)
	}

	loaded, created, err := ensureWithDir(t, dir, "self_signed")
	if err != nil {
		t.Fatal(err)
	}

	if !created || loaded.certificate == nil {
		t.Fatal("incomplete marked generation was not replaced")
	}

	for _, path := range []string{k.generationMarker(), k.certificateStage(), k.privateKeyStage()} {

		_, err = os.Stat(path)
		if !os.IsNotExist(err) {
			t.Fatalf("generation artifact remains at %s: %v", path, err)
		}
	}
}

func TestSelfSignedGenerationReplacesInvalidStagedPair(t *testing.T) {
	dir := t.TempDir()
	k := &Keeper{
		certificateFile: filepath.Join(dir, "server.crt"),
		privateKeyFile:  filepath.Join(dir, "server.key"),
		hostname:        "mail.test.example",
		mode:            "self_signed",
	}
	err := os.WriteFile(k.generationMarker(), []byte(generationMarkerText), 0600)
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile(k.privateKeyStage(), []byte("truncated key"), 0600)
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile(k.certificateStage(), []byte("truncated certificate"), 0644)
	if err != nil {
		t.Fatal(err)
	}

	loaded, created, err := ensureWithDir(t, dir, "self_signed")
	if err != nil {
		t.Fatal(err)
	}

	if !created || loaded.certificate == nil {
		t.Fatal("invalid marker-owned stages were not replaced")
	}
}

func TestSelfSignedRecoveryPreservesFinalFileWithIncompleteMarker(t *testing.T) {
	dir := t.TempDir()
	k := &Keeper{
		certificateFile: filepath.Join(dir, "server.crt"),
		privateKeyFile:  filepath.Join(dir, "server.key"),
		hostname:        "mail.test.example",
		mode:            "self_signed",
	}
	err := os.WriteFile(k.generationMarker(), []byte(generationMarkerText), 0600)
	if err != nil {
		t.Fatal(err)
	}

	body := []byte("operator certificate")
	err = os.WriteFile(k.certificateFile, body, 0644)
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = ensureWithDir(t, dir, "self_signed")
	if err == nil {
		t.Fatal("incomplete generation with final file succeeded")
	}

	got, err := os.ReadFile(k.certificateFile)
	if err != nil || !bytes.Equal(got, body) {
		t.Fatalf("final operator file changed: body=%q err=%v", got, err)
	}
}

func TestSelfSignedPathsConfinedToDataDirectory(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Server.DataDirectory = filepath.Join(dir, "data")
	cfg.TLS.CertificateFile = filepath.Join(dir, "outside.crt")
	cfg.TLS.PrivateKeyFile = filepath.Join(dir, "outside.key")
	_, _, err := Ensure(cfg)
	if err == nil || !strings.Contains(err.Error(), "beneath server.data_directory") {
		t.Fatalf("escaping generated paths accepted: %v", err)
	}

	for _, path := range []string{cfg.TLS.CertificateFile, cfg.TLS.PrivateKeyFile} {

		_, err := os.Stat(path)
		if !os.IsNotExist(err) {
			t.Fatalf("escaping path created: %s (%v)", path, err)
		}
	}
}

func TestLoadDoesNotGenerateMissingSelfSignedPair(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Server.Hostname = "mail.test.example"
	cfg.Server.DataDirectory = dir
	_, err := Load(cfg)
	if err == nil {
		t.Fatal("Load accepted missing certificate pair")
	}

	for _, name := range []string{"tls/server.crt", "tls/server.key"} {

		_, err := os.Stat(filepath.Join(dir, filepath.FromSlash(name)))
		if !os.IsNotExist(err) {
			t.Fatalf("Load generated %s: %v", name, err)
		}
	}
}

func TestFilesModeDoesNotOverwritePartial(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "server.key")
	err := os.WriteFile(keyPath, []byte("not-a-real-key"), 0600)
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = ensureWithDir(t, dir, "files")
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
	err := writeSelfSigned(dir, "other.example")
	if err != nil {
		t.Fatal(err)
	}

	k := &Keeper{
		certificateFile: filepath.Join(dir, "server.crt"),
		privateKeyFile:  filepath.Join(dir, "server.key"),
		hostname:        "mail.test.example",
		mode:            "files",
	}
	_, err = k.load()
	if err == nil {
		t.Fatal("expected hostname mismatch error")
	}
}

func TestCheckRejectsInvalidServingCertificates(t *testing.T) {
	tests := []servingCertificateCase{
		{
			name: "bad",
			prep: func(t *testing.T, dir string) {
				t.Helper()

				err := os.WriteFile(filepath.Join(dir, "server.crt"), []byte("bad certificate"), 0644)
				if err != nil {
					t.Fatal(err)
				}

				err = os.WriteFile(filepath.Join(dir, "server.key"), []byte("bad key"), 0600)
				if err != nil {
					t.Fatal(err)
				}
			},
			want: "failed to find any PEM data",
		},
		{
			name: "expired",
			prep: func(t *testing.T, dir string) {
				t.Helper()
				writeTestPair(t, dir, "mail.test.example", time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour))
			},
			want: "expired",
		},
		{
			name: "hostname mismatch",
			prep: func(t *testing.T, dir string) {
				t.Helper()

				err := writeSelfSigned(dir, "other.test.example")
				if err != nil {
					t.Fatal(err)
				}
			},
			want: "does not match hostname",
		},
		{
			name: "key mismatch",
			prep: func(t *testing.T, dir string) {
				t.Helper()

				err := writeSelfSigned(dir, "mail.test.example")
				if err != nil {
					t.Fatal(err)
				}

				replacement := t.TempDir()
				err = writeSelfSigned(replacement, "mail.test.example")
				if err != nil {
					t.Fatal(err)
				}

				key, err := os.ReadFile(filepath.Join(replacement, "server.key"))
				if err != nil {
					t.Fatal(err)
				}

				err = os.WriteFile(filepath.Join(dir, "server.key"), key, 0600)
				if err != nil {
					t.Fatal(err)
				}
			},
			want: "private key does not match",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			test.prep(t, dir)
			cfg := config.Default()
			cfg.Server.Hostname = "mail.test.example"
			cfg.TLS.Mode = "files"
			cfg.TLS.CertificateFile = filepath.Join(dir, "server.crt")
			cfg.TLS.PrivateKeyFile = filepath.Join(dir, "server.key")
			err := Check(cfg)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Check error=%v want %q", err, test.want)
			}
		})
	}
}

func TestCheckVerifiesTrustChainWithInjectedRoots(t *testing.T) {
	dir := t.TempDir()
	roots := writeTestChain(t, dir)
	cfg := config.Default()
	cfg.Server.Hostname = "mail.test.example"
	cfg.TLS.Mode = "files"
	cfg.TLS.CertificateFile = filepath.Join(dir, "server.crt")
	cfg.TLS.PrivateKeyFile = filepath.Join(dir, "server.key")
	err := CheckWithRoots(cfg, roots)
	if err != nil {
		t.Fatalf("trusted chain rejected: %v", err)
	}

	err = CheckWithRoots(cfg, x509.NewCertPool())
	if err == nil || !strings.Contains(err.Error(), "unknown authority") {
		t.Fatalf("untrusted chain accepted: %v", err)
	}

	chain, err := os.ReadFile(filepath.Join(dir, "server.crt"))
	if err != nil {
		t.Fatal(err)
	}

	leaf, _ := pem.Decode(chain)
	err = os.WriteFile(filepath.Join(dir, "server.crt"), pem.EncodeToMemory(leaf), 0644)
	if err != nil {
		t.Fatal(err)
	}

	err = CheckWithRoots(cfg, roots)
	if err == nil || !strings.Contains(err.Error(), "unknown authority") {
		t.Fatalf("missing intermediate accepted: %v", err)
	}
}

func writeTestChain(t *testing.T, dir string) *x509.CertPool {
	t.Helper()
	now := time.Now()
	newKey := func() *ecdsa.PrivateKey {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}

		return key
	}
	rootKey, intermediateKey, leafKey := newKey(), newKey(), newKey()
	root := &x509.Certificate{SerialNumber: big.NewInt(10), Subject: pkix.Name{CommonName: "test root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}

	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}

	intermediate := &x509.Certificate{SerialNumber: big.NewInt(11), Subject: pkix.Name{CommonName: "test intermediate"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	intermediateDER, err := x509.CreateCertificate(rand.Reader, intermediate, rootCert, &intermediateKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}

	intermediateCert, err := x509.ParseCertificate(intermediateDER)
	if err != nil {
		t.Fatal(err)
	}

	leaf := &x509.Certificate{SerialNumber: big.NewInt(12), DNSNames: []string{"mail.test.example"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, intermediateCert, &leafKey.PublicKey, intermediateKey)
	if err != nil {
		t.Fatal(err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: intermediateDER})...)
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile(filepath.Join(dir, "server.crt"), certPEM, 0644)
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile(filepath.Join(dir, "server.key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600)
	if err != nil {
		t.Fatal(err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(rootCert)
	return roots
}

func TestCertificateReadLimit(t *testing.T) {
	for _, name := range []string{"server.crt", "server.key"} {

		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			err := writeSelfSigned(dir, "mail.test.example")
			if err != nil {
				t.Fatal(err)
			}

			maximum := maxPrivateKeyBytes
			mode := os.FileMode(0600)
			if name == "server.crt" {
				maximum = maxCertificateBytes
				mode = 0644
			}

			err = os.WriteFile(filepath.Join(dir, name), make([]byte, maximum+1), mode)
			if err != nil {
				t.Fatal(err)
			}

			k := &Keeper{certificateFile: filepath.Join(dir, "server.crt"), privateKeyFile: filepath.Join(dir, "server.key"), mode: "files"}
			_, err = k.load()
			if err == nil || !strings.Contains(err.Error(), "read limit") {
				t.Fatalf("oversized %s error=%v", name, err)
			}
		})
	}
}

func writeTestPair(t *testing.T, dir, hostname string, notBefore, notAfter time.Time) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{hostname},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile(filepath.Join(dir, "server.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644)
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile(filepath.Join(dir, "server.key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}), 0600)
	if err != nil {
		t.Fatal(err)
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
	err = os.WriteFile(filepath.Join(dir, "server.crt"), []byte("broken"), 0644)
	if err != nil {
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

func TestHotReloadDetectsEqualMtimeReplacement(t *testing.T) {
	dir := t.TempDir()
	k, _, err := ensureWithDir(t, dir, "self_signed")
	if err != nil {
		t.Fatal(err)
	}

	oldLeaf, _ := x509.ParseCertificate(k.certificate.Certificate[0])
	replacement := t.TempDir()
	err = writeSelfSigned(replacement, "mail.test.example")
	if err != nil {
		t.Fatal(err)
	}

	stamp := time.Now().Add(-24 * time.Hour)

	for _, name := range []string{"server.crt", "server.key"} {

		body, err := os.ReadFile(filepath.Join(replacement, name))
		if err != nil {
			t.Fatal(err)
		}

		err = os.WriteFile(filepath.Join(dir, name), body, map[string]os.FileMode{"server.crt": 0644, "server.key": 0600}[name])
		if err != nil {
			t.Fatal(err)
		}

		err = os.Chtimes(filepath.Join(dir, name), stamp, stamp)
		if err != nil {
			t.Fatal(err)
		}
	}

	k.mu.Lock()
	k.checked = time.Time{}
	k.mu.Unlock()
	loaded, err := k.get(nil)
	if err != nil {
		t.Fatal(err)
	}

	newLeaf, _ := x509.ParseCertificate(loaded.Certificate[0])
	if oldLeaf.SerialNumber.Cmp(newLeaf.SerialNumber) == 0 {
		t.Fatal("equal/backdated mtime replacement was not reloaded")
	}
}

func TestHotReloadDetectsKeyOnlyReplacement(t *testing.T) {
	dir := t.TempDir()
	k, _, err := ensureWithDir(t, dir, "self_signed")
	if err != nil {
		t.Fatal(err)
	}

	old := k.certificate
	replacement := t.TempDir()
	err = writeSelfSigned(replacement, "mail.test.example")
	if err != nil {
		t.Fatal(err)
	}

	body, err := os.ReadFile(filepath.Join(replacement, "server.key"))
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile(filepath.Join(dir, "server.key"), body, 0600)
	if err != nil {
		t.Fatal(err)
	}

	stamp := time.Now().Add(-48 * time.Hour)
	err = os.Chtimes(filepath.Join(dir, "server.key"), stamp, stamp)
	if err != nil {
		t.Fatal(err)
	}

	var reported error
	k.SetReloadErrorHandler(func(err error) { reported = err })
	k.mu.Lock()
	k.checked = time.Time{}
	k.mu.Unlock()
	loaded, err := k.get(nil)
	if err != nil {
		t.Fatal(err)
	}

	if loaded != old || k.LastError() == nil || reported == nil {
		t.Fatal("key-only replacement was not detected and reported while retaining valid certificate")
	}
}

func TestReloadErrorHandlerCanInspectKeeper(t *testing.T) {
	dir := t.TempDir()
	k, _, err := ensureWithDir(t, dir, "self_signed")
	if err != nil {
		t.Fatal(err)
	}

	called := make(chan struct{})
	k.SetReloadErrorHandler(func(error) {
		_ = k.Status()
		_ = k.LastError()
		close(called)
	})

	err = os.WriteFile(filepath.Join(dir, "server.crt"), []byte("broken"), 0644)
	if err != nil {
		t.Fatal(err)
	}

	k.mu.Lock()
	k.checked = time.Time{}
	k.mu.Unlock()

	_, err = k.get(nil)
	if err != nil {
		t.Fatal(err)
	}

	select {
	case <-called:
	case <-time.After(time.Second):
		t.Fatal("reload callback deadlocked while inspecting keeper")
	}
}

func TestExpiredRetainedCertificateIsNotServed(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    now.Add(-2 * time.Hour),
		NotAfter:     now.Add(-time.Hour),
		DNSNames:     []string{"mail.test.example"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	k := &Keeper{certificate: &tls.Certificate{Certificate: [][]byte{der}}, checked: now}
	certificate, err := k.get(nil)
	if err == nil || certificate != nil {
		t.Fatalf("expired retained certificate served: certificate=%v err=%v", certificate != nil, err)
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
	err := k.generate("hn.example")
	if err != nil {
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
