package certupdater

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
)

// CertManager provides a higher-level interface over an AMT Client for
// managing the device's certificate store. It caches certificates and keys
// fetched from the device and keeps the cache in sync after every mutating
// operation so that round-trips are minimised.
//
// Call Refresh to populate the cache explicitly, or rely on the lazy
// initialisation that happens automatically on the first operation that needs
// the cached data.
type CertManager struct {
	client      *Client
	loaded      bool
	cert_to_key map[string]string
	certs       map[string]*x509.Certificate
	keys        map[string]*rsa.PublicKey
}

// NewCertManager creates a new CertManager connected to the AMT device
// described by params.
func NewCertManager(params Config) CertManager {
	return CertManager{
		client:      NewClient(params.AsClientParameters()),
		cert_to_key: make(map[string]string),
		certs:       make(map[string]*x509.Certificate),
		keys:        make(map[string]*rsa.PublicKey),
	}
}

// Close releases the underlying WS-Management connection.
func (cm *CertManager) Close() {
	cm.client.Close()
}

// refreshIfNeeded fetches certificates and keys from the device if the local
// cache has not been populated yet. Subsequent calls are no-ops.
func (cm *CertManager) refreshIfNeeded() error {
	if cm.loaded {
		return nil
	}
	return cm.Refresh()
}

// Refresh fetches the current certificate and key lists from the AMT device
// and rebuilds the internal cache. It also reconstructs the mapping from
// certificate handles to their corresponding key handles.
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
	// Mark loaded before building cert_to_key so that the GetKeyHandle call
	// below does not trigger another Refresh and cause infinite recursion.
	cm.loaded = true

	cm.cert_to_key = make(map[string]string, len(cm.certs))
	for certHandle, cert := range cm.certs {
		rsaKey, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			// Skip certificates whose public key is not RSA.
			continue
		}
		keyHandle, ok, err := cm.GetKeyHandle(rsaKey)
		if err != nil {
			return err
		}
		if ok {
			cm.cert_to_key[certHandle] = keyHandle
		}
	}

	return nil
}

// GetCurrentBundleHandle returns the AMT instance handles for the certificate
// and key that are currently configured as the device's TLS credential.
func (cm *CertManager) GetCurrentBundleHandle() (BundleHandles, error) {
	if err := cm.refreshIfNeeded(); err != nil {
		return BundleHandles{}, err
	}

	currentCertHandle, err := cm.client.GetCurrentCertHandle()
	if err != nil {
		return BundleHandles{}, err
	}

	currentKeyHandle, ok := cm.cert_to_key[currentCertHandle]
	if !ok {
		return BundleHandles{}, fmt.Errorf("no key handle found for current certificate handle %q", currentCertHandle)
	}
	return BundleHandles{
		Cert: currentCertHandle,
		Key:  currentKeyHandle,
	}, nil
}

// GetCertHandle searches the cached certificate list for a certificate equal
// to cert and returns its AMT instance handle. The second return value reports
// whether a match was found. The cache is populated automatically if it has
// not been loaded yet.
func (cm *CertManager) GetCertHandle(cert *x509.Certificate) (string, bool, error) {
	if err := cm.refreshIfNeeded(); err != nil {
		return "", false, err
	}

	for handle, c := range cm.certs {
		if c.Equal(cert) {
			return handle, true, nil
		}
	}
	return "", false, nil
}

// GetKeyHandle searches the cached key list for a public key equal to key and
// returns its AMT instance handle. The second return value reports whether a
// match was found. The cache is populated automatically if it has not been
// loaded yet.
func (cm *CertManager) GetKeyHandle(key *rsa.PublicKey) (string, bool, error) {
	if err := cm.refreshIfNeeded(); err != nil {
		return "", false, err
	}

	for handle, k := range cm.keys {
		if k.Equal(key) {
			return handle, true, nil
		}
	}
	return "", false, nil
}

// UploadOrGetKey uploads key to the AMT device unless an identical public key
// already exists in the device's key store, in which case the existing handle
// is returned. The local cache is updated on a successful upload.
func (cm *CertManager) UploadOrGetKey(key *rsa.PrivateKey) (string, error) {
	handle, ok, err := cm.GetKeyHandle(&key.PublicKey)
	if err != nil {
		return "", err
	}
	if ok {
		return handle, nil
	}
	handle, err = cm.client.UploadKey(key)
	if err != nil {
		return "", err
	}
	cm.keys[handle] = &key.PublicKey
	return handle, nil
}

// IsKeyInUse reports whether any certificate in the cached certificate store
// references the key identified by keyHandle. The cache is populated
// automatically if it has not been loaded yet.
func (cm *CertManager) IsKeyInUse(keyHandle string) (bool, error) {
	if err := cm.refreshIfNeeded(); err != nil {
		return false, err
	}

	for _, kh := range cm.cert_to_key {
		if kh == keyHandle {
			return true, nil
		}
	}
	return false, nil
}

// UploadOrGetCertificate uploads cert to the AMT device unless an identical
// certificate already exists in the device's certificate store, in which case
// the existing handle is returned. The local cache is updated on a successful
// upload.
func (cm *CertManager) UploadOrGetCertificate(cert *x509.Certificate) (string, error) {
	certHandle, ok, err := cm.GetCertHandle(cert)
	if err != nil {
		return "", err
	}
	if ok {
		return certHandle, nil
	}
	certHandle, err = cm.client.UploadCertificate(cert)
	if err != nil {
		return "", err
	}
	cm.certs[certHandle] = cert

	rsaKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if ok {
		keyHandle, ok, err := cm.GetKeyHandle(rsaKey)
		if err != nil {
			return "", err
		}
		if ok {
			cm.cert_to_key[certHandle] = keyHandle
		}
	}
	return certHandle, nil
}

// SetTLSCertificate configures the AMT device to use the certificate
// identified by bundleHandle as its active TLS credential.
func (cm *CertManager) SetTLSCertificate(bundleHandle BundleHandles) error {
	return cm.client.SetTLSCertificate(bundleHandle.Cert)
}

// DeleteCertificate removes the certificate identified by certHandle from the
// AMT device's certificate store and from the local cache.
func (cm *CertManager) DeleteCertificate(certHandle string) error {
	delete(cm.certs, certHandle)
	delete(cm.cert_to_key, certHandle)
	return cm.client.DeleteCertificate(certHandle)
}

// DeleteKey removes the key identified by keyHandle from the AMT device's key
// store and from the local cache.
func (cm *CertManager) DeleteKey(keyHandle string) error {
	delete(cm.keys, keyHandle)
	return cm.client.DeleteKey(keyHandle)
}

// UploadBundle uploads the certificate and private key in bundle to the AMT
// device (reusing any existing matching entries) and returns the resulting
// handles.
func (cm *CertManager) UploadBundle(bundle CertBundle) (BundleHandles, error) {
	keyHandle, err := cm.UploadOrGetKey(bundle.Key)
	if err != nil {
		return BundleHandles{}, err
	}

	certHandle, err := cm.UploadOrGetCertificate(bundle.Cert)
	if err != nil {
		return BundleHandles{}, err
	}

	return BundleHandles{
		Cert: certHandle,
		Key:  keyHandle,
	}, nil
}

// DeleteBundle removes the certificate and—if no other certificate references
// it—the private key identified by bundleHandle from the AMT device.
func (cm *CertManager) DeleteBundle(bundleHandle BundleHandles) error {
	if err := cm.DeleteCertificate(bundleHandle.Cert); err != nil {
		return err
	}
	inUse, err := cm.IsKeyInUse(bundleHandle.Key)
	if err != nil {
		return err
	}
	if !inUse {
		if err := cm.DeleteKey(bundleHandle.Key); err != nil {
			return err
		}
	}
	return nil
}
