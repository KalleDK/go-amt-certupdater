package certupdater

import (
	"os"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/client"
	"gopkg.in/yaml.v3"
)

// Config holds all settings required to connect to an AMT device and to
// locate the TLS certificate bundle that should be pushed to it.
type Config struct {
	Host                      string
	Username                  string
	Password                  string
	UseDigest                 bool   `yaml:"use_digest" mapstructure:"use_digest"`
	UseTLS                    bool   `yaml:"use_tls" mapstructure:"use_tls"`
	SelfSignedAllowed         bool   `yaml:"self_signed_allowed" mapstructure:"self_signed_allowed"`
	LogAMTMessages            bool   `yaml:"log_amt_messages" mapstructure:"log_amt_messages"`
	IsRedirection             bool   `yaml:"is_redirection" mapstructure:"is_redirection"`
	PinnedCert                string `yaml:"pinned_cert" mapstructure:"pinned_cert"`
	AllowInsecureCipherSuites bool   `yaml:"allow_insecure_cipher_suites" mapstructure:"allow_insecure_cipher_suites"`
	CertPath                  string `yaml:"cert_path" mapstructure:"cert_path"`
	KeyPath                   string `yaml:"key_path" mapstructure:"key_path"`
}

// AsClientParameters converts the connection-related fields of c into the
// client.Parameters type expected by the WS-Management library.
func (c *Config) AsClientParameters() client.Parameters {
	return client.Parameters{
		Target:                    c.Host,
		Username:                  c.Username,
		Password:                  c.Password,
		UseDigest:                 c.UseDigest,
		UseTLS:                    c.UseTLS,
		SelfSignedAllowed:         c.SelfSignedAllowed,
		LogAMTMessages:            c.LogAMTMessages,
		IsRedirection:             c.IsRedirection,
		PinnedCert:                c.PinnedCert,
		AllowInsecureCipherSuites: c.AllowInsecureCipherSuites,
	}
}

// LoadBundle reads the certificate and private key files referenced by
// CertPath and KeyPath and returns them as a CertBundle.
func (c *Config) LoadBundle() (CertBundle, error) {
	return LoadBundle(c.CertPath, c.KeyPath)
}

// LoadConfig reads a YAML configuration file from path and returns the parsed
// Config. Returns an error if the file cannot be read or does not contain
// valid YAML.
func LoadConfig(path string) (Config, error) {
	rawConfig, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}

	var config Config
	if err := yaml.Unmarshal(rawConfig, &config); err != nil {
		return Config{}, err
	}

	return config, nil
}
