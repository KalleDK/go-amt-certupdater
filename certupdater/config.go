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
	UseDigest                 bool   `yaml:"use_digest,omitempty"`
	UseTLS                    bool   `yaml:"use_tls,omitempty"`
	SelfSignedAllowed         bool   `yaml:"self_signed_allowed,omitempty"`
	LogAMTMessages            bool   `yaml:"log_amt_messages,omitempty"`
	IsRedirection             bool   `yaml:"is_redirection,omitempty"`
	PinnedCert                string `yaml:"pinned_cert,omitempty"`
	AllowInsecureCipherSuites bool   `yaml:"allow_insecure_cipher_suites,omitempty"`
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

	return client.Parameters{
		Target:                    config.Host,
		Username:                  config.Username,
		Password:                  config.Password,
		UseDigest:                 config.UseDigest,
		UseTLS:                    config.UseTLS,
		SelfSignedAllowed:         config.SelfSignedAllowed,
		LogAMTMessages:            config.LogAMTMessages,
		IsRedirection:             config.IsRedirection,
		PinnedCert:                config.PinnedCert,
		AllowInsecureCipherSuites: config.AllowInsecureCipherSuites,
	}, nil
}
