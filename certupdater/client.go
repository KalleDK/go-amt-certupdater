package certupdater

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/client"
)

// Client wraps a WS-Management connection to an AMT device and exposes the
// certificate-management operations needed by CertManager.
type Client struct {
	wsman wsman.Messages
}

// Close terminates the underlying WS-Management connection.
func (c *Client) Close() {
	c.wsman.Client.CloseConnection()
}

// GetKeys retrieves all RSA public keys stored in the AMT device's key store
// and returns them indexed by their AMT instance handle.
func (c *Client) GetKeys() (map[string]*rsa.PublicKey, error) {
	resp, err := c.wsman.AMT.PublicPrivateKeyPair.Enumerate()
	if err != nil {
		return nil, fmt.Errorf("enumerate AMT public keys: %w", err)
	}

	resp, err = c.wsman.AMT.PublicPrivateKeyPair.Pull(resp.Body.EnumerateResponse.EnumerationContext)
	if err != nil {
		return nil, fmt.Errorf("pull AMT public keys: %w", err)
	}

	result := make(map[string]*rsa.PublicKey)
	for _, item := range resp.Body.RefinedPullResponse.PublicPrivateKeyPairItems {
		dec, err := base64.StdEncoding.DecodeString(item.DERKey)
		if err != nil {
			return nil, fmt.Errorf("decode public key DER for %s: %w", item.InstanceID, err)
		}

		pubKey, err := x509.ParsePKCS1PublicKey(dec)
		if err != nil {
			return nil, fmt.Errorf("parse public key for %s: %w", item.InstanceID, err)
		}
		result[item.InstanceID] = pubKey
	}
	return result, nil
}

// GetCertificates retrieves all X.509 certificates stored in the AMT device's
// certificate store and returns them indexed by their AMT instance handle.
func (c *Client) GetCertificates() (map[string]*x509.Certificate, error) {
	resp, err := c.wsman.AMT.PublicKeyCertificate.Enumerate()
	if err != nil {
		return nil, fmt.Errorf("enumerate AMT certificates: %w", err)
	}

	resp, err = c.wsman.AMT.PublicKeyCertificate.Pull(resp.Body.EnumerateResponse.EnumerationContext)
	if err != nil {
		return nil, fmt.Errorf("pull AMT certificates: %w", err)
	}

	certificates := make(map[string]*x509.Certificate)
	for _, item := range resp.Body.RefinedPullResponse.PublicKeyCertificateItems {
		derData, err := base64.StdEncoding.DecodeString(item.X509Certificate)
		if err != nil {
			return nil, fmt.Errorf("decode certificate DER for %s: %w", item.InstanceID, err)
		}
		cert, err := x509.ParseCertificate(derData)
		if err != nil {
			return nil, fmt.Errorf("parse certificate for %s: %w", item.InstanceID, err)
		}
		certificates[item.InstanceID] = cert
	}
	return certificates, nil
}

// GetCurrentCertHandle returns the AMT instance handle of the certificate that
// is currently configured as the device's active TLS credential.
func (c *Client) GetCurrentCertHandle() (string, error) {
	current, err := c.wsman.AMT.TLSCredentialContext.Enumerate()
	if err != nil {
		return "", fmt.Errorf("enumerate TLS credential context: %w", err)
	}
	current, err = c.wsman.AMT.TLSCredentialContext.Pull(current.Body.EnumerateResponse.EnumerationContext)
	if err != nil {
		return "", fmt.Errorf("pull TLS credential context: %w", err)
	}

	items := current.Body.PullResponse.CredentialContextItems
	if len(items) == 0 {
		return "", fmt.Errorf("no TLS credential context found on device")
	}
	return items[0].ElementInContext.ReferenceParameters.SelectorSet.Selectors[0].Text, nil
}

// UploadKey uploads an RSA private key to the AMT device's key store and
// returns the new AMT instance handle.
func (c *Client) UploadKey(key *rsa.PrivateKey) (string, error) {
	privKeyDER := x509.MarshalPKCS1PrivateKey(key)
	resp, err := c.wsman.AMT.PublicKeyManagementService.AddKey(base64.StdEncoding.EncodeToString(privKeyDER))
	if err != nil {
		return "", fmt.Errorf("add key to AMT: %w", err)
	}
	if resp.Body.AddKey_OUTPUT.ReturnValue != 0 {
		return "", fmt.Errorf("AMT AddKey returned non-zero status: %d", resp.Body.AddKey_OUTPUT.ReturnValue)
	}
	return resp.Body.AddKey_OUTPUT.CreatedKey.ReferenceParameters.SelectorSet.Selectors[0].Text, nil
}

// UploadCertificate uploads an X.509 certificate to the AMT device's
// certificate store and returns the new AMT instance handle.
func (c *Client) UploadCertificate(cert *x509.Certificate) (string, error) {
	resp, err := c.wsman.AMT.PublicKeyManagementService.AddCertificate(base64.StdEncoding.EncodeToString(cert.Raw))
	if err != nil {
		return "", fmt.Errorf("add certificate to AMT: %w", err)
	}
	certHandle := resp.Body.AddCertificate_OUTPUT.CreatedCertificate.ReferenceParameters.SelectorSet.Selectors[0].Text
	return certHandle, nil
}

// SetTLSCertificate configures the AMT device to use the certificate
// identified by certHandle as its active TLS credential.
func (c *Client) SetTLSCertificate(certHandle string) error {
	_, err := c.wsman.AMT.TLSCredentialContext.Put(certHandle)
	return err
}

// DeleteCertificate removes the certificate identified by certHandle from the
// AMT device's certificate store.
func (c *Client) DeleteCertificate(certHandle string) error {
	_, err := c.wsman.AMT.PublicKeyCertificate.Delete(certHandle)
	return err
}

// DeleteKey removes the key identified by keyHandle from the AMT device's key
// store.
func (c *Client) DeleteKey(keyHandle string) error {
	_, err := c.wsman.AMT.PublicPrivateKeyPair.Delete(keyHandle)
	return err
}

// NewClient creates a new Client connected to the AMT device described by
// params.
func NewClient(params client.Parameters) *Client {
	return &Client{
		wsman: wsman.NewMessages(params),
	}
}
