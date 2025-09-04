package certupdater

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/client"
)

type CertManager struct {
	client      *Client
	cert_to_key map[string]string
	certs       map[string]*x509.Certificate
	keys        map[string]*rsa.PublicKey
}

func NewCertManager(params client.Parameters) CertManager {
	return CertManager{
		client: NewClient(params),
	}
}

func (cm *CertManager) Close() {
	cm.client.Close()
}

func (cm *CertManager) Refresh() error {
	certs, err := cm.client.GetCertificates()
	if err != nil {
		return err
	}

	keys, err := cm.client.GetKeys()
	if err != nil {
		return err
	}

	cm.certs = certs
	cm.keys = keys

	cm.cert_to_key = make(map[string]string, len(cm.certs))
	for cert_handle, cert := range cm.certs {
		key_handle, ok := cm.GetKeyHandle(cert.PublicKey.(*rsa.PublicKey))
		if ok {
			cm.cert_to_key[cert_handle] = key_handle
		}
	}

	return nil
}

func (cm *CertManager) GetCurrentBundleHandle() (BundleHandles, error) {
	current_cert_handle, err := cm.client.GetCurrentCertHandle()
	if err != nil {
		return BundleHandles{}, err
	}
	current_key_handle, ok := cm.cert_to_key[current_cert_handle]
	if !ok {
		return BundleHandles{}, fmt.Errorf("current cert handle not found")
	}
	return BundleHandles{
		Cert: current_cert_handle,
		Key:  current_key_handle,
	}, nil
}

func (cm *CertManager) GetCertHandle(cert *x509.Certificate) (string, bool) {
	if cm.certs == nil {
		cm.Refresh()
	}

	if len(cm.certs) == 0 {
		return "", false
	}

	for handle, c := range cm.certs {
		if c.Equal(cert) {
			return handle, true
		}
	}
	return "", false
}

func (cm *CertManager) GetKeyHandle(key *rsa.PublicKey) (string, bool) {
	if cm.keys == nil {
		cm.Refresh()
	}

	if len(cm.keys) == 0 {
		return "", false
	}

	for handle, k := range cm.keys {
		if k.Equal(key) {
			return handle, true
		}
	}
	return "", false
}

func (cm *CertManager) UploadOrGetKey(key *rsa.PrivateKey) (string, error) {
	handle, ok := cm.GetKeyHandle(&key.PublicKey)
	if ok {
		return handle, nil
	}
	handle, err := cm.client.UploadKey(key)
	if err != nil {
		return "", err
	}
	cm.keys[handle] = &key.PublicKey
	return handle, nil
}

func (cm *CertManager) IsKeyInUse(key_handle string) bool {
	if cm.cert_to_key == nil {
		cm.Refresh()
	}

	for _, kh := range cm.cert_to_key {
		if kh == key_handle {
			return true
		}
	}
	return false
}

func (cm *CertManager) UploadOrGetCertificate(cert *x509.Certificate) (string, error) {
	cert_handle, ok := cm.GetCertHandle(cert)
	if ok {
		return cert_handle, nil
	}
	cert_handle, err := cm.client.UploadCertificate(cert)
	if err != nil {
		return "", err
	}
	cm.certs[cert_handle] = cert

	key_handle, ok := cm.GetKeyHandle(cert.PublicKey.(*rsa.PublicKey))
	if ok {
		cm.cert_to_key[cert_handle] = key_handle
	}
	return cert_handle, nil
}

func (cm *CertManager) SetTLSCertificate(bundle_handle BundleHandles) error {
	return cm.client.SetTLSCertificate(bundle_handle.Cert)
}

func (cm *CertManager) DeleteCertificate(cert_handle string) error {
	delete(cm.certs, cert_handle)
	return cm.client.DeleteCertificate(cert_handle)
}

func (cm *CertManager) DeleteKey(key_handle string) error {
	delete(cm.keys, key_handle)
	return cm.client.DeleteKey(key_handle)
}

func (cm *CertManager) UploadBundle(bundle CertBundle) (BundleHandles, error) {
	key_handle, err := cm.UploadOrGetKey(bundle.Key)
	if err != nil {
		return BundleHandles{}, err
	}

	cert_handle, err := cm.UploadOrGetCertificate(bundle.Cert)
	if err != nil {
		return BundleHandles{}, err
	}

	return BundleHandles{
		Cert: cert_handle,
		Key:  key_handle,
	}, nil
}

func (cm *CertManager) DeleteBundle(bundle_handle BundleHandles) error {
	if err := cm.DeleteCertificate(bundle_handle.Cert); err != nil {
		return err
	}
	if !cm.IsKeyInUse(bundle_handle.Key) {
		if err := cm.DeleteKey(bundle_handle.Key); err != nil {
			return err
		}
	}
	return nil
}
