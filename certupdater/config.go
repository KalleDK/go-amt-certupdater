package certupdater

import (
	"os"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/client"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Host                      string
	Username                  string
	Password                  string
	UseDigest                 bool   `yaml:"use_digest,omitempty" mapstructure:"use_digest"`
	UseTLS                    bool   `yaml:"use_tls,omitempty" mapstructure:"use_tls"`
	SelfSignedAllowed         bool   `yaml:"self_signed_allowed,omitempty" mapstructure:"self_signed_allowed"`
	LogAMTMessages            bool   `yaml:"log_amt_messages,omitempty" mapstructure:"log_amt_messages"`
	IsRedirection             bool   `yaml:"is_redirection,omitempty" mapstructure:"is_redirection"`
	PinnedCert                string `yaml:"pinned_cert,omitempty" mapstructure:"pinned_cert"`
	AllowInsecureCipherSuites bool   `yaml:"allow_insecure_cipher_suites,omitempty" mapstructure:"allow_insecure_cipher_suites"`
	CertPath                  string `yaml:"cert_path,omitempty" mapstructure:"cert_path"`
	KeyPath                   string `yaml:"key_path,omitempty" mapstructure:"key_path"`
}

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

func (c *Config) LoadBundle() (CertBundle, error) {

	bundle, err := LoadBundle(c.CertPath, c.KeyPath)
	if err != nil {
		return CertBundle{}, err
	}

	return bundle, nil
}

func LoadConfig(path string) (client.Parameters, error) {
	raw_config, err := os.ReadFile(path)
	if err != nil {
		return client.Parameters{}, err
	}

	var config Config
	if err := yaml.Unmarshal(raw_config, &config); err != nil {
		return client.Parameters{}, err
	}

	return config.AsClientParameters(), nil
}
