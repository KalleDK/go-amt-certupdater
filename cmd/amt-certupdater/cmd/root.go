/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"
	"os"

	certupdater "github.com/KalleDK/go-amt-certupdater/certupdater"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func loadConfig(v *viper.Viper, cfg *certupdater.Config) error {
	v.SetConfigFile(viper.GetString("config"))

	if err := v.ReadInConfig(); err != nil { // Handle errors reading the config file
		return err
	}
	if err := v.Unmarshal(&cfg); err != nil {
		return err
	}
	fmt.Printf("Using config: %+v\n", *cfg)
	return nil
}

func loadConfigGlobal(cfg *certupdater.Config) error {

	viper.SetConfigFile(viper.GetString("config"))

	if err := viper.ReadInConfig(); err != nil { // Handle errors reading the config file
		return err
	}
	if err := viper.Unmarshal(&cfg); err != nil {
		return err
	}

	return nil
}

var cfg certupdater.Config

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "go-amt-certupdater",
	Short: "Renew cert on amt devices using certs from lego",
	Long:  ``,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if err := loadConfigGlobal(&cfg); err != nil {
			return err
		}
		return nil
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

type Settings struct {
	Config string
}

const PREFIX = "AMT"

func withPrefix(s string) string {
	return fmt.Sprintf("%s_%s", PREFIX, s)
}

func addConfigFlags(cmd *cobra.Command, v *viper.Viper) {
	v.SetEnvPrefix(PREFIX)
	v.AutomaticEnv()

	cmd.Flags().Bool("help", false, "help for "+cmd.Name())
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
	viper.SetEnvPrefix("AMT")
	viper.AutomaticEnv()
	rootCmd.PersistentFlags().StringP("config", "c", "config.yml", "config file")
	viper.BindPFlag("config", rootCmd.PersistentFlags().Lookup("config"))

}
