/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"

	certupdater "github.com/KalleDK/go-amt-certupdater/certupdater"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var replaceViper = viper.New()

var replaceCmd = &cobra.Command{
	Use:   "replace",
	Short: "",
	Long:  ``,

	RunE: func(cmd *cobra.Command, args []string) error {
		var cfg certupdater.Config
		if err := loadConfig(replaceViper, &cfg); err != nil {
			return err
		}

		bundle, err := cfg.LoadBundle()
		if err != nil {
			fmt.Println("Error loading Lego bundle:", err)
			return err
		}
		fmt.Println("Loaded certificate for:", bundle.Cert.Subject.CommonName)

		mgr := certupdater.NewCertManager(cfg)
		defer mgr.Close()

		current_bundle, err := mgr.GetCurrentBundleHandle()
		if err != nil {
			fmt.Println("Error getting current TLS handles:", err)
			return err
		}
		fmt.Println("Current certificate handle:", current_bundle.Cert)
		fmt.Println("Current key handle:", current_bundle.Key)

		new_bundle, err := mgr.UploadBundle(bundle)
		if err != nil {
			fmt.Println("Error uploading new certificate bundle:", err)
			return err
		}
		fmt.Println("Uploaded new certificate handle:", new_bundle.Cert)
		fmt.Println("Uploaded new key handle:", new_bundle.Key)

		if new_bundle.Cert == current_bundle.Cert {
			fmt.Println("New certificate is the same as current certificate.")
			return nil
		}

		if err := mgr.SetTLSCertificate(new_bundle); err != nil {
			fmt.Println("Error setting TLS certificate:", err)
			return err
		}
		fmt.Println("Set new TLS certificate to:", new_bundle.Cert)

		if err := mgr.DeleteBundle(current_bundle); err != nil {
			fmt.Println("Error deleting old certificate bundle:", err)
			return err
		}
		fmt.Println("Deleted old certificate bundle:", current_bundle.Cert)

		fmt.Println("Done")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(replaceCmd)
	addConfigFlags(replaceCmd, replaceViper)
}
