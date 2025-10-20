package main

import (
	"fmt"
	"os"

	"github.com/Neda-Zarei/deep-guard/internal/config"
	"github.com/Neda-Zarei/deep-guard/internal/logger"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile string
	cfg     *config.Config
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "deepguard",
	Short: "AI-powered vulnerability scanner for modern applications",
	Long: `DeepGuard is a fast, AI-powered vulnerability scanner that detects security
issues in JavaScript/TypeScript, Python, and Java applications.

It uses Tree-sitter for code parsing, BM25 search for pattern retrieval,
and GPT-4o for intelligent vulnerability analysis.`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	// Global flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is .deepguard.yaml)")
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "enable verbose debug logging")

	// Bind global flags to viper
	viper.BindPFlag("verbose", rootCmd.PersistentFlags().Lookup("verbose"))
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	var err error
	cfg, err = config.LoadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	// Initialize logger based on config
	logger.InitLogger(cfg.Verbose)

	log.Debug().
		Str("component", "cli").
		Str("operation", "init_config").
		Msg("Configuration loaded")
}
