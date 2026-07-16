// Package cmd implements the replace sub-command.
package cmd

import (
	"fmt"

	certupdater "github.com/KalleDK/go-amt-certupdater/certupdater"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var replaceViper = viper.New()

// replaceCmd uploads a new certificate bundle to the AMT device, activates it
// as the TLS credential, and removes the previously active bundle.
var replaceCmd = &cobra.Command{
	Use:   "replace",
	Short: "Replace the active TLS certificate on the AMT device",
	Long: `replace uploads a new certificate and private key to the AMT device,
sets it as the active TLS credential, then deletes the old certificate bundle.

The certificate and key paths can be supplied via the config file, the --cert
and --key flags, or the AMT_CERT / AMT_KEY (and LEGO_CERT_PATH /
LEGO_CERT_KEY_PATH) environment variables.`,

	RunE: func(cmd *cobra.Command, args []string) error {
		var cfg certupdater.Config
		if err := loadConfig(replaceViper, &cfg); err != nil {
			return err
		}

		bundle, err := cfg.LoadBundle()
		if err != nil {
			return fmt.Errorf("load certificate bundle: %w", err)
		}
		fmt.Println("Loaded certificate for:", bundle.Cert.Subject.CommonName)

		mgr := certupdater.NewCertManager(cfg)
		defer mgr.Close()

		currentBundle, err := mgr.GetCurrentBundleHandle()
		if err != nil {
			return fmt.Errorf("get current TLS handles: %w", err)
		}
		fmt.Println("Current certificate handle:", currentBundle.Cert)
		fmt.Println("Current key handle:", currentBundle.Key)

		newBundle, err := mgr.UploadBundle(bundle)
		if err != nil {
			return fmt.Errorf("upload new certificate bundle: %w", err)
		}
		fmt.Println("Uploaded certificate handle:", newBundle.Cert)
		fmt.Println("Uploaded key handle:", newBundle.Key)

		if newBundle.Cert == currentBundle.Cert {
			fmt.Println("Certificate is already up to date.")
			return nil
		}

		if err := mgr.SetTLSCertificate(newBundle); err != nil {
			return fmt.Errorf("set TLS certificate: %w", err)
		}
		fmt.Println("Activated new TLS certificate:", newBundle.Cert)

		if err := mgr.DeleteBundle(currentBundle); err != nil {
			return fmt.Errorf("delete old certificate bundle: %w", err)
		}
		fmt.Println("Deleted old certificate bundle:", currentBundle.Cert)

		fmt.Println("Done.")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(replaceCmd)
	addConfigFlags(replaceCmd, replaceViper)
}
