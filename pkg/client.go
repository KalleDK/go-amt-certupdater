package certupdater

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/client"
)

type Client struct {
	wsman wsman.Messages
}

func (c *Client) Close() {
	c.wsman.Client.CloseConnection()
}

func (c *Client) GetKeys() (map[string]*rsa.PublicKey, error) {
	resp, err := c.wsman.AMT.PublicPrivateKeyPair.Enumerate()
	if err != nil {
		fmt.Println("Error enumerating AMT Public Key:", err)
		return nil, err
	}

	resp, err = c.wsman.AMT.PublicPrivateKeyPair.Pull(resp.Body.EnumerateResponse.EnumerationContext)
	if err != nil {
		fmt.Println("Error pulling AMT Public Key:", err)
		return nil, err
	}

	result := make(map[string]*rsa.PublicKey)

	for _, item := range resp.Body.RefinedPullResponse.PublicPrivateKeyPairItems {
		dec, err := base64.StdEncoding.DecodeString(item.DERKey)
		if err != nil {
			fmt.Println("Error decoding server public key:", err)
			return nil, err
		}

		server_pubkey, err := x509.ParsePKCS1PublicKey(dec)
		if err != nil {
			fmt.Println("Error parsing server public key:", err)
			return nil, err
		}
		result[item.InstanceID] = server_pubkey

	}
	return result, nil
}

func (c *Client) GetCertificates() (map[string]*x509.Certificate, error) {
	resp, err := c.wsman.AMT.PublicKeyCertificate.Enumerate()
	if err != nil {
		fmt.Println("Error enumerating public key certificates:", err)
		return nil, err
	}

	resp, err = c.wsman.AMT.PublicKeyCertificate.Pull(resp.Body.EnumerateResponse.EnumerationContext)
	if err != nil {
		fmt.Println("Error pulling public key certificates:", err)
		return nil, err
	}

	certificates := make(map[string]*x509.Certificate)
	for _, item := range resp.Body.RefinedPullResponse.PublicKeyCertificateItems {
		der_data, err := base64.StdEncoding.DecodeString(item.X509Certificate)
		if err != nil {
			fmt.Println("Error decoding certificate:", err)
			return nil, err
		}
		cert, err := x509.ParseCertificate(der_data)
		if err != nil {
			fmt.Println("Error parsing certificate:", err)
			return nil, err
		}

		certificates[item.InstanceID] = cert
	}
	return certificates, nil
}

func (c *Client) GetCurrentCertHandle() (string, error) {
	current, err := c.wsman.AMT.TLSCredentialContext.Enumerate()
	if err != nil {
		fmt.Println("Error getting current TLS credential context:", err)
		return "", err
	}
	current, err = c.wsman.AMT.TLSCredentialContext.Pull(current.Body.EnumerateResponse.EnumerationContext)
	if err != nil {
		fmt.Println("Error getting current TLS credential context:", err)
		return "", err
	}
	return current.Body.PullResponse.CredentialContextItems[0].ElementInContext.ReferenceParameters.SelectorSet.Selectors[0].Text, nil

}

func (c *Client) UploadKey(key *rsa.PrivateKey) (string, error) {
	priv_key_der := x509.MarshalPKCS1PrivateKey(key)
	respadd, err := c.wsman.AMT.PublicKeyManagementService.AddKey(base64.StdEncoding.EncodeToString(priv_key_der))
	if err != nil {
		return "", err
	}
	if respadd.Body.AddKey_OUTPUT.ReturnValue != 0 {
		return "", fmt.Errorf("error adding public key: %v", respadd.Body.AddKey_OUTPUT.ReturnValue)
	}

	return respadd.Body.AddKey_OUTPUT.CreatedKey.ReferenceParameters.SelectorSet.Selectors[0].Text, nil
}

func (c *Client) UploadCertificate(cert *x509.Certificate) (string, error) {
	resp, err := c.wsman.AMT.PublicKeyManagementService.AddCertificate(base64.StdEncoding.EncodeToString(cert.Raw))
	if err != nil {
		fmt.Println("Error adding certificate:", err)
		return "", err
	}
	cert_handle := resp.Body.AddCertificate_OUTPUT.CreatedCertificate.ReferenceParameters.SelectorSet.Selectors[0].Text
	return cert_handle, nil
}

func (c *Client) SetTLSCertificate(certHandle string) error {
	_, err := c.wsman.AMT.TLSCredentialContext.Put(certHandle)
	return err
}

func (c *Client) DeleteCertificate(certHandle string) error {
	_, err := c.wsman.AMT.PublicKeyCertificate.Delete(certHandle)
	if err != nil {
		return err
	}
	return nil
}

func (c *Client) DeleteKey(keyHandle string) error {
	_, err := c.wsman.AMT.PublicPrivateKeyPair.Delete(keyHandle)
	if err != nil {
		return err
	}
	return nil
}

func Connect(params client.Parameters) Client {
	return Client{
		wsman: wsman.NewMessages(params),
	}
}
