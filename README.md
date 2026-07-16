# go-amt-certupdater

A command-line tool that replaces the TLS certificate on Intel AMT (Active Management Technology) devices. It is designed to integrate with certificate renewal tools such as [lego](https://go-acme.github.io/lego/) so that AMT devices always present an up-to-date certificate.

## How it works

1. Reads a new certificate and private key from disk (e.g. files written by lego after a successful renewal).
2. Uploads the certificate and key to the AMT device's key store (reusing any matching entry that already exists).
3. Activates the new certificate as the device's TLS credential.
4. Deletes the old certificate bundle, leaving only the new one.

## Installation

### Pre-built binaries

Download the latest release for your platform from the [Releases](../../releases) page and extract the archive.

### Build from source

```sh
go install github.com/KalleDK/go-amt-certupdater/cmd/amt-certupdater@latest
```

Or clone and build:

```sh
git clone https://github.com/KalleDK/go-amt-certupdater.git
cd go-amt-certupdater
go build -o amt-certupdater ./cmd/amt-certupdater
```

## Configuration

Settings are resolved in priority order (highest first):

1. Command-line flags
2. Environment variables
3. Config file (YAML)

### Config file

Create a YAML file (default: `config.yml` in the current directory):

```yaml
# Hostname or IP address of the AMT device.
host: amt.server.local

# AMT credentials.
username: admin
password: secretpassword

# Use HTTP Digest authentication (required by most AMT devices).
use_digest: true

# Connect over TLS.
use_tls: true

# Allow the AMT device to present a self-signed TLS certificate during
# the management session (useful before the first certificate update).
self_signed_allowed: true

# Optional: pin the AMT device's TLS certificate (PEM-encoded string).
# pinned_cert: ""

# Optional: log raw WS-Management XML messages (useful for debugging).
# log_amt_messages: false

# Optional: allow weak/legacy TLS cipher suites.
# allow_insecure_cipher_suites: false

# Paths to the certificate and private key to push to the AMT device.
cert_path: /etc/lego/certs/amt.server.local.crt
key_path: /etc/lego/certs/amt.server.local.key
```

Pass an alternative config file with the `--config` flag:

```sh
amt-certupdater --config /etc/amt/config.yml replace
```

### Environment variables

All settings can be overridden via environment variables with the `AMT_` prefix:

| Variable | Config key | Description |
|---|---|---|
| `AMT_HOST` | `host` | AMT device hostname / IP |
| `AMT_USERNAME` | `username` | AMT username |
| `AMT_PASSWORD` | `password` | AMT password |
| `AMT_CERT` or `LEGO_CERT_PATH` | `cert_path` | Path to the certificate file |
| `AMT_KEY` or `LEGO_CERT_KEY_PATH` | `key_path` | Path to the private key file |

`LEGO_CERT_PATH` and `LEGO_CERT_KEY_PATH` are set automatically by lego when running a `--run-hook`, making integration straightforward.

## Usage

### Replace the active TLS certificate

```sh
amt-certupdater replace
```

With explicit flags:

```sh
amt-certupdater replace \
  --config config.yml \
  --cert /path/to/cert.pem \
  --key  /path/to/key.pem
```

### Integration with lego

Add a run-hook to your lego renewal command:

```sh
lego --email you@example.com \
     --domains amt.server.local \
     --run-hook "amt-certupdater --config /etc/amt/config.yml replace" \
     run
```

lego sets `LEGO_CERT_PATH` and `LEGO_CERT_KEY_PATH` before invoking the hook, so you don't need to specify `--cert` or `--key` explicitly.

## Library usage

The `certupdater` package can also be used as a Go library:

```go
import "github.com/KalleDK/go-amt-certupdater/certupdater"

cfg := certupdater.Config{
    Host:              "amt.server.local",
    Username:          "admin",
    Password:          "secret",
    UseDigest:         true,
    UseTLS:            true,
    SelfSignedAllowed: true,
    CertPath:          "/path/to/cert.pem",
    KeyPath:           "/path/to/key.pem",
}

bundle, err := cfg.LoadBundle()
// ...

mgr := certupdater.NewCertManager(cfg)
defer mgr.Close()

current, err := mgr.GetCurrentBundleHandle()
// ...

newHandles, err := mgr.UploadBundle(bundle)
// ...

if err := mgr.SetTLSCertificate(newHandles); err != nil {
    // handle error
}
if err := mgr.DeleteBundle(current); err != nil {
    // handle error
}
```

## License

See [LICENSE](LICENSE).
