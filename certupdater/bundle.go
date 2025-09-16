package certupdater

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

type BundleHandles struct {
	Cert string
	Key  string
}

type CertBundle struct {
	Cert *x509.Certificate
	Key  *rsa.PrivateKey
}

func loadPrivateKey(filename string) (*rsa.PrivateKey, error) {
	key_pem, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	key_der, _ := pem.Decode(key_pem)

	rsa_key, err := x509.ParsePKCS1PrivateKey(key_der.Bytes)
	if err != nil {
		return nil, err
	}
	return rsa_key, nil
}

func loadCert(filename string) (*x509.Certificate, error) {
	cert_pem, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	cert_der, _ := pem.Decode(cert_pem)

	cert, err := x509.ParseCertificate(cert_der.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func LoadBundle(cert_path, key_path string) (CertBundle, error) {
	fmt.Println("Using private key path:", key_path)
	fmt.Println("Using certificate path:", cert_path)

	cert, err := loadCert(cert_path)
	if err != nil {
		return CertBundle{}, err
	}

	key, err := loadPrivateKey(key_path)
	if err != nil {
		return CertBundle{}, err
	}

	return CertBundle{
		Cert: cert,
		Key:  key,
	}, nil
}
