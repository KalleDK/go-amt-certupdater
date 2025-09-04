/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"
	"os"

	certupdater "github.com/KalleDK/go-amt-certupdater/certupdater"
	"github.com/spf13/cobra"
)

func loadLegoBundle() (certupdater.CertBundle, error) {
	private_key_path := os.Getenv("LEGO_CERT_KEY_PATH")
	cert_path := os.Getenv("LEGO_CERT_PATH")

	fmt.Println("Using private key path:", private_key_path)
	fmt.Println("Using certificate path:", cert_path)

	bundle, err := certupdater.LoadBundle(cert_path, private_key_path)
	if err != nil {
		return certupdater.CertBundle{}, err
	}

	return bundle, nil
}

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "go-amt-certupdater",
	Short: "Renew cert on amt devices using certs from lego",
	Long:  ``,

	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Starting")

		config, err := certupdater.LoadConfig(cfgFile)
		if err != nil {
			fmt.Println("Error loading config:", err)
			return
		}

		bundle, err := loadLegoBundle()
		if err != nil {
			fmt.Println("Error loading Lego bundle:", err)
			return
		}
		fmt.Println("Loaded certificate for:", bundle.Cert.Subject.CommonName)

		mgr := certupdater.NewCertManager(config)
		defer mgr.Close()

		current_bundle, err := mgr.GetCurrentBundleHandle()
		if err != nil {
			fmt.Println("Error getting current TLS handles:", err)
			return
		}
		fmt.Println("Current certificate handle:", current_bundle.Cert)
		fmt.Println("Current key handle:", current_bundle.Key)

		new_bundle, err := mgr.UploadBundle(bundle)
		if err != nil {
			fmt.Println("Error uploading new certificate bundle:", err)
			return
		}
		fmt.Println("Uploaded new certificate handle:", new_bundle.Cert)
		fmt.Println("Uploaded new key handle:", new_bundle.Key)

		if new_bundle.Cert == current_bundle.Cert {
			fmt.Println("New certificate is the same as current certificate.")
			return
		}

		if err := mgr.SetTLSCertificate(new_bundle); err != nil {
			fmt.Println("Error setting TLS certificate:", err)
			return
		}
		fmt.Println("Set new TLS certificate to:", new_bundle.Cert)

		if err := mgr.DeleteBundle(current_bundle); err != nil {
			fmt.Println("Error deleting old certificate bundle:", err)
			return
		}

		fmt.Println("Done")
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

var cfgFile string

func init() {
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "config.yml", "config file")
}
