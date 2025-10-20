package main

import (
	"fmt"

	"github.com/Neda-Zarei/deep-guard/internal/kb"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var kbCmd = &cobra.Command{
	Use:   "kb",
	Short: "Knowledge Base management commands",
	Long:  `Commands for managing and validating the vulnerability pattern knowledge base.`,
}

var kbValidateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate Knowledge Base schema and integrity",
	Long: `Validate the Knowledge Base YAML files for:
  - Schema compliance (required fields present)
  - No duplicate vulnerability IDs
  - Valid severity levels
  - Proper pattern syntax

This command is useful for KB contributors to verify their changes before submission.`,
	Example: `  # Validate the default knowledge base
  deepguard kb validate

  # Validate a custom knowledge base
  deepguard kb validate --kb-path ./custom-kb/`,
	RunE: runKBValidate,
}

func init() {
	rootCmd.AddCommand(kbCmd)
	kbCmd.AddCommand(kbValidateCmd)

	// KB path flag (optional, defaults to .deepguard/kb/)
	kbValidateCmd.Flags().String("kb-path", ".deepguard/kb/", "path to knowledge base directory")
}

// runKBValidate validates the knowledge base
func runKBValidate(cmd *cobra.Command, args []string) error {
	kbPath, _ := cmd.Flags().GetString("kb-path")

	log.Info().
		Str("component", "kb").
		Str("operation", "validate").
		Str("path", kbPath).
		Msg("Starting knowledge base validation")

	fmt.Printf("Validating knowledge base at: %s\n", kbPath)

	// Load and validate KB directory
	entries, err := kb.LoadKBDirectory(kbPath)
	if err != nil {
		log.Error().
			Err(err).
			Str("component", "kb").
			Str("path", kbPath).
			Msg("Knowledge base validation failed")

		fmt.Printf("\n❌ Validation failed: %v\n", err)
		return err
	}

	// Success
	log.Info().
		Str("component", "kb").
		Int("count", len(entries)).
		Msg("Knowledge base validation successful")

	fmt.Printf("\n✅ Validation successful!\n")
	fmt.Printf("   Loaded %d vulnerability entries\n", len(entries))

	// List all loaded entries
	if len(entries) > 0 {
		fmt.Println("\nKnowledge Base Entries:")
		for _, entry := range entries {
			fmt.Printf("  - %s: %s\n", entry.ID, entry.Title)
		}
	}

	return nil
}
