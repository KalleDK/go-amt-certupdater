package certupdater

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// generateTestBundle creates a self-signed RSA certificate and private key
// suitable for use in tests.
func generateTestBundle(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Fatalf("parse generated certificate: %v", err)
	}

	return cert, key
}

// writePEMFiles writes a certificate and key to temporary PEM files and
// returns their paths. The caller does not need to remove the files; the test
// cleanup function handles that.
func writePEMFiles(t *testing.T, cert *x509.Certificate, key *rsa.PrivateKey) (certPath, keyPath string) {
	t.Helper()

	dir := t.TempDir()
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")

	certFile, err := os.Create(certPath)
	if err != nil {
		t.Fatalf("create cert file: %v", err)
	}
	defer certFile.Close()
	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
		t.Fatalf("encode cert PEM: %v", err)
	}

	keyFile, err := os.Create(keyPath)
	if err != nil {
		t.Fatalf("create key file: %v", err)
	}
	defer keyFile.Close()
	keyDER := x509.MarshalPKCS1PrivateKey(key)
	if err := pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyDER}); err != nil {
		t.Fatalf("encode key PEM: %v", err)
	}

	return certPath, keyPath
}

func TestLoadBundle_Success(t *testing.T) {
	cert, key := generateTestBundle(t)
	certPath, keyPath := writePEMFiles(t, cert, key)

	bundle, err := LoadBundle(certPath, keyPath)
	if err != nil {
		t.Fatalf("LoadBundle: %v", err)
	}

	if !bundle.Cert.Equal(cert) {
		t.Error("loaded certificate does not match original")
	}
	if bundle.Key.D.Cmp(key.D) != 0 {
		t.Error("loaded private key does not match original")
	}
}

func TestLoadBundle_MissingCertFile(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "nonexistent.pem")
	keyPath := filepath.Join(dir, "key.pem")

	_, err := LoadBundle(certPath, keyPath)
	if err == nil {
		t.Fatal("expected error for missing cert file, got nil")
	}
}

func TestLoadBundle_MissingKeyFile(t *testing.T) {
	cert, key := generateTestBundle(t)
	certPath, _ := writePEMFiles(t, cert, key)
	keyPath := filepath.Join(t.TempDir(), "nonexistent.pem")

	_, err := LoadBundle(certPath, keyPath)
	if err == nil {
		t.Fatal("expected error for missing key file, got nil")
	}
}

func TestLoadBundle_InvalidCertPEM(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(certPath, []byte("not valid pem"), 0600); err != nil {
		t.Fatalf("write cert file: %v", err)
	}

	_, key := generateTestBundle(t)
	// Write a valid key file to a separate temp dir.
	keyDir := t.TempDir()
	keyPath := filepath.Join(keyDir, "key.pem")
	keyFile, err := os.Create(keyPath)
	if err != nil {
		t.Fatalf("create key file: %v", err)
	}
	defer keyFile.Close()
	keyDER := x509.MarshalPKCS1PrivateKey(key)
	if encErr := pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyDER}); encErr != nil {
		t.Fatalf("encode key PEM: %v", encErr)
	}

	_, err = LoadBundle(certPath, keyPath)
	if err == nil {
		t.Fatal("expected error for invalid cert PEM, got nil")
	}
}

func TestLoadBundle_InvalidKeyPEM(t *testing.T) {
	cert, key := generateTestBundle(t)
	certPath, _ := writePEMFiles(t, cert, key)

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(keyPath, []byte("not valid pem"), 0600); err != nil {
		t.Fatalf("write key file: %v", err)
	}

	_, err := LoadBundle(certPath, keyPath)
	if err == nil {
		t.Fatal("expected error for invalid key PEM, got nil")
	}
}

func TestLoadBundle_WrongCertData(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	// Write a PEM block with garbage DER content.
	certFile, err := os.Create(certPath)
	if err != nil {
		t.Fatalf("create cert file: %v", err)
	}
	defer certFile.Close()
	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: []byte("garbage")}); err != nil {
		t.Fatalf("encode cert PEM: %v", err)
	}

	_, key := generateTestBundle(t)
	keyDir := t.TempDir()
	keyPath := filepath.Join(keyDir, "key.pem")
	keyFile, err := os.Create(keyPath)
	if err != nil {
		t.Fatalf("create key file: %v", err)
	}
	defer keyFile.Close()
	keyDER := x509.MarshalPKCS1PrivateKey(key)
	if encErr := pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyDER}); encErr != nil {
		t.Fatalf("encode key PEM: %v", encErr)
	}

	_, err = LoadBundle(certPath, keyPath)
	if err == nil {
		t.Fatal("expected error for invalid cert DER, got nil")
	}
}

func TestLoadBundle_WrongKeyData(t *testing.T) {
	cert, _ := generateTestBundle(t)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	certFile, err := os.Create(certPath)
	if err != nil {
		t.Fatalf("create cert file: %v", err)
	}
	defer certFile.Close()
	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
		t.Fatalf("encode cert PEM: %v", err)
	}

	keyPath := filepath.Join(dir, "key.pem")
	keyFile, err := os.Create(keyPath)
	if err != nil {
		t.Fatalf("create key file: %v", err)
	}
	defer keyFile.Close()
	if err := pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte("garbage")}); err != nil {
		t.Fatalf("encode key PEM: %v", err)
	}

	_, err = LoadBundle(certPath, keyPath)
	if err == nil {
		t.Fatal("expected error for invalid key DER, got nil")
	}
}
