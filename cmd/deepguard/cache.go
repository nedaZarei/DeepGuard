package main

import (
	"fmt"
	"os"

	"github.com/Neda-Zarei/deep-guard/internal/cache"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var cacheCmd = &cobra.Command{
	Use:   "cache",
	Short: "Manage DeepGuard cache",
	Long: `Manage DeepGuard's cache system including KB index and API responses.

The cache improves performance by:
  - Persisting KB index to avoid rebuilds
  - Caching API responses during development (optional)`,
}

var cacheClearCmd = &cobra.Command{
	Use:   "clear",
	Short: "Clear all cache data",
	Long: `Clear all cached data including KB index and API responses.

This will force a full rebuild of the KB index on next scan and
remove all cached API responses.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		clearKB, _ := cmd.Flags().GetBool("kb-index")
		clearAPI, _ := cmd.Flags().GetBool("api")
		clearAll, _ := cmd.Flags().GetBool("all")

		if !clearKB && !clearAPI && !clearAll {
			// Default to clearing all if no specific flags provided
			clearAll = true
		}

		if clearAll || clearKB {
			kbCache := cache.NewKBIndexCache("./internal/kb/data", log.Logger)
			if err := kbCache.Clear(); err != nil {
				return fmt.Errorf("failed to clear KB index cache: %w", err)
			}
			fmt.Println("✓ Cleared KB index cache")
		}

		if clearAll || clearAPI {
			apiCache := cache.NewAPIResponseCache(true, log.Logger)
			if err := apiCache.Clear(); err != nil {
				return fmt.Errorf("failed to clear API cache: %w", err)
			}
			fmt.Println("✓ Cleared API response cache")
		}

		return nil
	},
}

var cacheStatsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Show cache statistics",
	Long:  `Display statistics about cached data including entry counts, size, and hit rates.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("DeepGuard Cache Statistics")
		fmt.Println("===========================\n")

		// KB Index Cache Stats
		fmt.Println("KB Index Cache:")
		fmt.Println("---------------")
		kbCache := cache.NewKBIndexCache("./internal/kb/data", log.Logger)
		kbStats, err := kbCache.GetStats()
		if err != nil {
			return fmt.Errorf("failed to get KB cache stats: %w", err)
		}

		if exists, ok := kbStats["exists"].(bool); !ok || !exists {
			fmt.Println("  Status: Not cached")
		} else {
			fmt.Printf("  Status: Cached\n")
			if hash, ok := kbStats["kb_hash"].(string); ok {
				fmt.Printf("  KB Hash: %s\n", hash)
			}
			if buildTime, ok := kbStats["build_time"].(string); ok {
				fmt.Printf("  Build Time: %s\n", buildTime)
			}
			if entries, ok := kbStats["entry_count"].(int); ok {
				fmt.Printf("  Entries: %d\n", entries)
			}
			if sizeMB, ok := kbStats["size_mb"].(float64); ok {
				fmt.Printf("  Size: %.2f MB\n", sizeMB)
			}
			if ageHours, ok := kbStats["age_hours"].(float64); ok {
				fmt.Printf("  Age: %.1f hours\n", ageHours)
			}
		}

		fmt.Println()

		// API Response Cache Stats
		fmt.Println("API Response Cache:")
		fmt.Println("-------------------")

		// Check if cache is enabled via environment
		cacheEnabled := os.Getenv("DEEPGUARD_CACHE_API_RESPONSES") == "true"
		if !cacheEnabled {
			fmt.Println("  Status: Disabled")
			fmt.Println("  (Enable with DEEPGUARD_CACHE_API_RESPONSES=true)")
		} else {
			apiCache := cache.NewAPIResponseCache(true, log.Logger)
			apiStats, err := apiCache.GetStats()
			if err != nil {
				return fmt.Errorf("failed to get API cache stats: %w", err)
			}

			fmt.Printf("  Status: Enabled\n")
			fmt.Printf("  Total Entries: %d\n", apiStats.TotalEntries)
			fmt.Printf("  Cache Hits: %d\n", apiStats.Hits)
			fmt.Printf("  Cache Misses: %d\n", apiStats.Misses)
			if apiStats.Hits+apiStats.Misses > 0 {
				hitRate := apiCache.GetHitRate()
				fmt.Printf("  Hit Rate: %.1f%%\n", hitRate)
			}
			if !apiStats.LastClean.IsZero() {
				fmt.Printf("  Last Cleaned: %s\n", apiStats.LastClean.Format("2006-01-02 15:04:05"))
			}
			if apiStats.TotalSaved > 0 {
				fmt.Printf("  Estimated Savings: $%.2f\n", apiStats.TotalSaved)
			}
		}

		return nil
	},
}

var cacheCleanCmd = &cobra.Command{
	Use:   "clean",
	Short: "Clean old cache entries",
	Long: `Remove cache entries older than 30 days.

This helps manage disk space while preserving recent cache data.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cacheEnabled := os.Getenv("DEEPGUARD_CACHE_API_RESPONSES") == "true"
		if !cacheEnabled {
			fmt.Println("API cache is disabled. Nothing to clean.")
			return nil
		}

		apiCache := cache.NewAPIResponseCache(true, log.Logger)
		if err := apiCache.CleanOld(); err != nil {
			return fmt.Errorf("failed to clean old cache entries: %w", err)
		}

		fmt.Println("✓ Cleaned old cache entries (older than 30 days)")
		return nil
	},
}

func init() {
	// Add subcommands
	cacheCmd.AddCommand(cacheClearCmd)
	cacheCmd.AddCommand(cacheStatsCmd)
	cacheCmd.AddCommand(cacheCleanCmd)

	// Flags for clear command
	cacheClearCmd.Flags().Bool("kb-index", false, "Clear only KB index cache")
	cacheClearCmd.Flags().Bool("api", false, "Clear only API response cache")
	cacheClearCmd.Flags().Bool("all", false, "Clear all caches (default)")

	// Register with root command
	rootCmd.AddCommand(cacheCmd)
}
