// Package certupdater provides functionality to manage TLS certificates on
// Intel AMT (Active Management Technology) devices via the WS-Management
// protocol. It supports uploading certificate bundles, replacing the active
// TLS certificate, and cleaning up stale certificates and keys.
package certupdater

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// BundleHandles holds the AMT instance identifiers for a certificate and its
// associated private key as returned by the AMT device.
type BundleHandles struct {
	Cert string
	Key  string
}

// CertBundle holds a parsed X.509 certificate together with the corresponding
// RSA private key.
type CertBundle struct {
	Cert *x509.Certificate
	Key  *rsa.PrivateKey
}

// loadPrivateKey reads a PEM-encoded PKCS#1 RSA private key from disk.
func loadPrivateKey(filename string) (*rsa.PrivateKey, error) {
	keyPEM, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	keyDER, _ := pem.Decode(keyPEM)
	if keyDER == nil {
		return nil, fmt.Errorf("no PEM block found in %s", filename)
	}

	rsaKey, err := x509.ParsePKCS1PrivateKey(keyDER.Bytes)
	if err != nil {
		return nil, err
	}
	return rsaKey, nil
}

// loadCert reads a PEM-encoded X.509 certificate from disk.
func loadCert(filename string) (*x509.Certificate, error) {
	certPEM, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	certDER, _ := pem.Decode(certPEM)
	if certDER == nil {
		return nil, fmt.Errorf("no PEM block found in %s", filename)
	}

	cert, err := x509.ParseCertificate(certDER.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

// LoadBundle reads a PEM-encoded X.509 certificate and a PEM-encoded PKCS#1
// RSA private key from disk and returns them as a CertBundle.
func LoadBundle(certPath, keyPath string) (CertBundle, error) {
	cert, err := loadCert(certPath)
	if err != nil {
		return CertBundle{}, err
	}

	key, err := loadPrivateKey(keyPath)
	if err != nil {
		return CertBundle{}, err
	}

	return CertBundle{
		Cert: cert,
		Key:  key,
	}, nil
}
