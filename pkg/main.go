package certupdater

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/client"
	"gopkg.in/yaml.v3"
)

func loadConfig(path string) (client.Parameters, error) {
	raw_config, err := os.ReadFile(path)
	if err != nil {
		return client.Parameters{}, err
	}

	var params client.Parameters
	if err := yaml.Unmarshal(raw_config, &params); err != nil {
		return client.Parameters{}, err
	}

	return params, nil
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

func Main(config_file string) {
	fmt.Println("Starting")
	private_key_path := os.Getenv("LEGO_CERT_KEY_PATH")
	cert_path := os.Getenv("LEGO_CERT_PATH")
	domain := os.Getenv("LEGO_CERT_DOMAIN")

	fmt.Println("Using private key path:", private_key_path)
	fmt.Println("Using certificate path:", cert_path)
	fmt.Println("Using domain:", domain)

	config, err := loadConfig(config_file)
	if err != nil {
		fmt.Println("Error loading config:", err)
		return
	}

	// 3.a Create an instance to send the messages and defer the close of the connection.
	// NewMessages instantiates a new Messages class with client connection parameters.
	// Messages implements client.WSMan, amt.Messages, cim.Messages, and ips.Messages.
	client := Connect(config)
	defer client.Close()

	keys, err := client.GetKeys()
	if err != nil {
		fmt.Println("Error getting keys:", err)
		return
	}

	certs, err := client.GetCertificates()
	if err != nil {
		fmt.Println("Error getting certificates:", err)
		return
	}

	cert_to_key := make(map[string]string)
	for certID, cert := range certs {
		for keyID, key := range keys {
			if key.Equal(cert.PublicKey) {
				cert_to_key[certID] = keyID
				break
			}
		}
	}

	current_cert, err := client.GetCurrentCertHandle()
	if err != nil {
		fmt.Println("Error getting current certificate:", err)
		return
	}
	current_key := cert_to_key[current_cert]
	fmt.Println("Current certificate:", current_cert)
	fmt.Println("Current key:", current_key)

	priv_key_name, err := func() (string, error) {
		priv_key, err := loadPrivateKey(private_key_path)
		if err != nil {
			return "", err
		}
		for keyID, key := range keys {
			if priv_key.PublicKey.Equal(key) {
				fmt.Printf("Found matching key for private key: %s\n", keyID)
				return keyID, nil
			} else {
				fmt.Printf("No matching key found for private key: %s\n", keyID)
			}
		}
		return client.UploadKey(priv_key)
	}()
	if err != nil {
		fmt.Println("Error uploading private key:", err)
		return
	}

	fmt.Println("Private key handle:", priv_key_name)

	cert_name, err := func() (string, error) {
		new_cert, err := loadCert(cert_path)
		if err != nil {
			return "", err
		}
		for certID, cert := range certs {
			if new_cert.Equal(cert) {
				fmt.Printf("Found matching cert for certificate: %s\n", certID)
				return certID, nil
			} else {
				fmt.Printf("No matching cert found for certificate: %s\n", certID)
			}
		}
		return client.UploadCertificate(new_cert)
	}()
	if err != nil {
		fmt.Println("Error uploading certificate:", err)
		return
	}
	fmt.Println("New certificate handle:", cert_name)

	if cert_name == current_cert {
		fmt.Println("New certificate is the same as current certificate.")
		return
	}

	if err := client.SetTLSCertificate(cert_name); err != nil {
		fmt.Println("Error setting TLS certificate:", err)
		return
	}
	fmt.Println("Set new TLS certificate to:", cert_name)

	if err := client.DeleteCertificate(current_cert); err != nil {
		fmt.Println("Error deleting certificate:", err)
		return
	}
	fmt.Println("Deleted old certificate:", current_cert)

	delete(cert_to_key, current_cert)
	key_in_use := func() bool {
		for _, keyID := range cert_to_key {
			if keyID == current_key {
				return true
			}
		}
		return false
	}()
	if !key_in_use {
		if err := client.DeleteKey(current_key); err != nil {
			fmt.Println("Error deleting key:", err)
			return
		}
		fmt.Println("Deleted old key:", current_key)
	} else {
		fmt.Println("Key is still in use:", current_key)
	}

}
