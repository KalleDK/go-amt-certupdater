// Package cmd implements the command-line interface for amt-certupdater using
// cobra and viper. Configuration can be supplied via a YAML file, environment
// variables (prefix AMT_), or command-line flags.
package cmd

import (
	"os"

	certupdater "github.com/KalleDK/go-amt-certupdater/certupdater"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func loadConfigGlobal(cfg *certupdater.Config) error {
	viper.SetConfigFile(viper.GetString("config"))

	if err := viper.ReadInConfig(); err != nil {
		return err
	}
	if err := viper.Unmarshal(&cfg); err != nil {
		return err
	}

	return nil
}

func loadConfig(v *viper.Viper, cfg *certupdater.Config) error {
	v.SetConfigFile(viper.GetString("config"))

	if err := v.ReadInConfig(); err != nil {
		return err
	}
	if err := v.Unmarshal(cfg); err != nil {
		return err
	}
	return nil
}

var cfg certupdater.Config

// rootCmd is the base command. Sub-commands (e.g. replace) are registered via
// their own init functions.
var rootCmd = &cobra.Command{
	Use:   "amt-certupdater",
	Short: "Renew TLS certificates on Intel AMT devices",
	Long: `amt-certupdater replaces the TLS certificate on one or more Intel AMT
devices. It is designed to be called from a certificate-renewal hook (e.g.
lego's --run-hook) so that the AMT device always uses the latest certificate.`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		return loadConfigGlobal(&cfg)
	},
}

// Execute runs the root command and exits with a non-zero status on failure.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

const envPrefix = "AMT"

func withPrefix(s string) string {
	return envPrefix + "_" + s
}

// addConfigFlags registers the connection and bundle flags onto cmd and binds
// them to the supplied viper instance so that per-sub-command configuration
// works correctly alongside the global config file.
func addConfigFlags(cmd *cobra.Command, v *viper.Viper) {
	v.SetEnvPrefix(envPrefix)
	v.AutomaticEnv()

	cmd.Flags().StringP("host", "h", "", "host to connect to")
	v.BindPFlag("host", cmd.Flags().Lookup("host"))
	cmd.Flags().StringP("username", "u", "", "username to authenticate with")
	v.BindPFlag("username", cmd.Flags().Lookup("username"))
	cmd.Flags().StringP("password", "p", "", "password to authenticate with")
	v.BindPFlag("password", cmd.Flags().Lookup("password"))
	cmd.Flags().String("cert", "", "path to certificate file")
	v.BindPFlag("cert_path", cmd.Flags().Lookup("cert"))
	v.BindEnv("cert_path", withPrefix("CERT"), "LEGO_CERT_PATH")
	cmd.Flags().String("key", "", "path to private key file")
	v.BindPFlag("key_path", cmd.Flags().Lookup("key"))
	v.BindEnv("key_path", withPrefix("KEY"), "LEGO_CERT_KEY_PATH")
}

func init() {
	viper.SetEnvPrefix(envPrefix)
	viper.AutomaticEnv()
	rootCmd.PersistentFlags().StringP("config", "c", "config.yml", "config file")
	viper.BindPFlag("config", rootCmd.PersistentFlags().Lookup("config"))
}
