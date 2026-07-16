package certupdater

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/client"
)

func TestAsClientParameters(t *testing.T) {
	cfg := Config{
		Host:                      "amt.example.com",
		Username:                  "admin",
		Password:                  "secret",
		UseDigest:                 true,
		UseTLS:                    true,
		SelfSignedAllowed:         false,
		LogAMTMessages:            true,
		IsRedirection:             false,
		PinnedCert:                "pinned",
		AllowInsecureCipherSuites: false,
		CertPath:                  "/tmp/cert.pem",
		KeyPath:                   "/tmp/key.pem",
	}

	want := client.Parameters{
		Target:                    "amt.example.com",
		Username:                  "admin",
		Password:                  "secret",
		UseDigest:                 true,
		UseTLS:                    true,
		SelfSignedAllowed:         false,
		LogAMTMessages:            true,
		IsRedirection:             false,
		PinnedCert:                "pinned",
		AllowInsecureCipherSuites: false,
	}

	got := cfg.AsClientParameters()

	if got.Target != want.Target {
		t.Errorf("Target: got %q, want %q", got.Target, want.Target)
	}
	if got.Username != want.Username {
		t.Errorf("Username: got %q, want %q", got.Username, want.Username)
	}
	if got.Password != want.Password {
		t.Errorf("Password: got %q, want %q", got.Password, want.Password)
	}
	if got.UseDigest != want.UseDigest {
		t.Errorf("UseDigest: got %v, want %v", got.UseDigest, want.UseDigest)
	}
	if got.UseTLS != want.UseTLS {
		t.Errorf("UseTLS: got %v, want %v", got.UseTLS, want.UseTLS)
	}
	if got.SelfSignedAllowed != want.SelfSignedAllowed {
		t.Errorf("SelfSignedAllowed: got %v, want %v", got.SelfSignedAllowed, want.SelfSignedAllowed)
	}
	if got.LogAMTMessages != want.LogAMTMessages {
		t.Errorf("LogAMTMessages: got %v, want %v", got.LogAMTMessages, want.LogAMTMessages)
	}
	if got.IsRedirection != want.IsRedirection {
		t.Errorf("IsRedirection: got %v, want %v", got.IsRedirection, want.IsRedirection)
	}
	if got.PinnedCert != want.PinnedCert {
		t.Errorf("PinnedCert: got %q, want %q", got.PinnedCert, want.PinnedCert)
	}
	if got.AllowInsecureCipherSuites != want.AllowInsecureCipherSuites {
		t.Errorf("AllowInsecureCipherSuites: got %v, want %v", got.AllowInsecureCipherSuites, want.AllowInsecureCipherSuites)
	}
}

func TestAsClientParameters_CertKeyNotExposed(t *testing.T) {
	// CertPath and KeyPath are not part of client.Parameters; verify they are
	// intentionally absent from the conversion output.
	cfg := Config{
		CertPath: "/some/cert.pem",
		KeyPath:  "/some/key.pem",
	}
	params := cfg.AsClientParameters()

	// client.Parameters has no cert/key path fields; the struct should have
	// zero values for all fields since Config had only CertPath/KeyPath set.
	if params.Target != "" {
		t.Errorf("Target should be empty, got %q", params.Target)
	}
}

func TestLoadConfig_ValidYAML(t *testing.T) {
	yaml := `
host: amt.example.com
username: admin
password: secret
use_digest: true
use_tls: true
self_signed_allowed: true
cert_path: /tmp/cert.pem
key_path: /tmp/key.pem
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(path, []byte(yaml), 0600); err != nil {
		t.Fatalf("write config file: %v", err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	if cfg.Host != "amt.example.com" {
		t.Errorf("Host: got %q, want %q", cfg.Host, "amt.example.com")
	}
	if cfg.Username != "admin" {
		t.Errorf("Username: got %q, want %q", cfg.Username, "admin")
	}
	if cfg.Password != "secret" {
		t.Errorf("Password: got %q, want %q", cfg.Password, "secret")
	}
	if !cfg.UseDigest {
		t.Error("UseDigest: got false, want true")
	}
	if !cfg.UseTLS {
		t.Error("UseTLS: got false, want true")
	}
	if !cfg.SelfSignedAllowed {
		t.Error("SelfSignedAllowed: got false, want true")
	}
	if cfg.CertPath != "/tmp/cert.pem" {
		t.Errorf("CertPath: got %q, want %q", cfg.CertPath, "/tmp/cert.pem")
	}
	if cfg.KeyPath != "/tmp/key.pem" {
		t.Errorf("KeyPath: got %q, want %q", cfg.KeyPath, "/tmp/key.pem")
	}
}

func TestLoadConfig_MissingFile(t *testing.T) {
	_, err := LoadConfig(filepath.Join(t.TempDir(), "nonexistent.yml"))
	if err == nil {
		t.Fatal("expected error for missing config file, got nil")
	}
}

func TestLoadConfig_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(path, []byte(":\tinvalid: yaml: [\n"), 0600); err != nil {
		t.Fatalf("write config file: %v", err)
	}

	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("expected error for invalid YAML, got nil")
	}
}

func TestLoadConfig_PartialYAML(t *testing.T) {
	// Unset fields should have zero values.
	yaml := "host: only-host.example.com\n"
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(path, []byte(yaml), 0600); err != nil {
		t.Fatalf("write config file: %v", err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	if cfg.Host != "only-host.example.com" {
		t.Errorf("Host: got %q, want %q", cfg.Host, "only-host.example.com")
	}
	if cfg.Username != "" {
		t.Errorf("Username should be empty, got %q", cfg.Username)
	}
	if cfg.UseTLS {
		t.Error("UseTLS should default to false")
	}
}
