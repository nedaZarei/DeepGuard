package main

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

var (
	// Version information (will be set via build flags in production)
	Version   = "v0.1.0"
	GitCommit = "dev"
	BuildDate = "unknown"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Display version information",
	Long:  `Display the version number, Git commit hash, and build metadata for DeepGuard.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("DeepGuard %s\n", Version)
		fmt.Printf("Git commit: %s\n", GitCommit)
		fmt.Printf("Build date: %s\n", BuildDate)
		fmt.Printf("Go version: %s\n", runtime.Version())
		fmt.Printf("OS/Arch: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
