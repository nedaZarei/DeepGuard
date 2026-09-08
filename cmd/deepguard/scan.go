package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Neda-Zarei/deep-guard/internal/chunker"
	"github.com/Neda-Zarei/deep-guard/internal/config"
	"github.com/Neda-Zarei/deep-guard/internal/discovery"
	"github.com/Neda-Zarei/deep-guard/internal/kb"
	"github.com/Neda-Zarei/deep-guard/internal/llm"
	"github.com/Neda-Zarei/deep-guard/internal/logger"
	"github.com/Neda-Zarei/deep-guard/internal/orchestrator"
	"github.com/Neda-Zarei/deep-guard/internal/parser"
	"github.com/Neda-Zarei/deep-guard/internal/rag"
	"github.com/Neda-Zarei/deep-guard/internal/report"
	"github.com/Neda-Zarei/deep-guard/internal/reporting"
	"github.com/Neda-Zarei/deep-guard/pkg/types"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan a directory for security vulnerabilities",
	Long: `Scan analyzes source code in the target directory for security vulnerabilities
using AI-powered analysis with GPT-4o.

The scanner parses code into function-level chunks, retrieves relevant vulnerability
patterns from the knowledge base, and performs intelligent security analysis.`,
	Example: `  # Basic scan
  deepguard scan --path ./my-project

  # Scan with custom output directory
  deepguard scan --path ./my-project --output ./security-reports

  # Scan specific languages only
  deepguard scan --path ./my-project --languages js,ts

  # Scan with verbose logging
  deepguard scan --path ./my-project --verbose`,
	PreRunE: validateScanFlags,
	RunE:    runScan,
}

func init() {
	rootCmd.AddCommand(scanCmd)

	// Required flags
	scanCmd.Flags().StringP("path", "p", "", "target directory to scan (required)")
	scanCmd.MarkFlagRequired("path")

	// Optional flags
	scanCmd.Flags().StringP("output", "o", "./reports/", "output directory for scan reports")
	scanCmd.Flags().StringSliceP("languages", "l", []string{"js", "ts", "python", "java"}, "languages to scan (comma-separated)")
	scanCmd.Flags().Float64("confidence-threshold", 0.5, "minimum confidence score (0.0-1.0) for reporting findings")

	// Bind flags to viper config keys
	viper.BindPFlag("scan_path", scanCmd.Flags().Lookup("path"))
	viper.BindPFlag("output_dir", scanCmd.Flags().Lookup("output"))
	viper.BindPFlag("languages", scanCmd.Flags().Lookup("languages"))
	viper.BindPFlag("confidence_threshold", scanCmd.Flags().Lookup("confidence-threshold"))
}

// validateScanFlags validates all scan command flags before execution
func validateScanFlags(cmd *cobra.Command, args []string) error {
	// Get values from viper (which has flag bindings from init())
	scanPath := viper.GetString("scan_path")
	outputDir := viper.GetString("output_dir")
	languages := viper.GetStringSlice("languages")
	verbose := viper.GetBool("verbose")

	// Re-initialize logger with updated verbose flag
	logger.InitLogger(verbose)

	log.Debug().
		Str("component", "cli").
		Str("operation", "validate_flags").
		Str("scan_path", scanPath).
		Msg("Validating scan flags")

	// Validate scan_path exists and is a directory
	if scanPath == "" {
		return fmt.Errorf("--path flag is required")
	}

	info, err := os.Stat(scanPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("scan path does not exist: %s", scanPath)
		}
		return fmt.Errorf("cannot access scan path: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("scan path must be a directory: %s", scanPath)
	}

	log.Debug().
		Str("component", "cli").
		Str("path", scanPath).
		Msg("Scan path validated")

	// Create output directory if it doesn't exist
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	log.Debug().
		Str("component", "cli").
		Str("output_dir", outputDir).
		Msg("Output directory ready")

	// Validate languages
	validLanguages := map[string]bool{
		"js":     true,
		"ts":     true,
		"python": true,
		"java":   true,
		"c":      true,
		"cpp":    true,
	}

	filteredLanguages := []string{}
	for _, lang := range languages {
		lang = strings.TrimSpace(strings.ToLower(lang))
		if validLanguages[lang] {
			filteredLanguages = append(filteredLanguages, lang)
		} else {
			log.Warn().
				Str("component", "cli").
				Str("language", lang).
				Msg("Skipping invalid language")
		}
	}

	if len(filteredLanguages) == 0 {
		return fmt.Errorf("no valid languages specified (must be one of: js, ts, python, java, c, cpp)")
	}

	log.Debug().
		Str("component", "cli").
		Strs("languages", filteredLanguages).
		Msg("Languages validated")

	// Rebuild config from validated values
	var loadErr error
	cfg, loadErr = config.LoadConfig()
	if loadErr != nil {
		return fmt.Errorf("failed to load configuration: %w", loadErr)
	}

	// Override with validated flag values
	cfg.ScanPath = scanPath
	cfg.OutputDir = outputDir
	cfg.Languages = filteredLanguages
	cfg.Verbose = verbose

	// Run full config validation
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("configuration validation failed: %w", err)
	}

	return nil
}

// runScan executes the vulnerability scan
func runScan(cmd *cobra.Command, args []string) error {
	log.Info().
		Str("component", "scanner").
		Str("operation", "scan_start").
		Str("path", cfg.ScanPath).
		Msg("Starting vulnerability scan")

	log.Info().
		Str("component", "config").
		Str("output_dir", cfg.OutputDir).
		Strs("languages", cfg.Languages).
		Str("model", cfg.OpenAIModel).
		Float64("budget_cap", cfg.BudgetCap).
		Float64("confidence_threshold", cfg.ConfidenceThreshold).
		Msg("Scan configuration")

	// Discover files
	ignoreFile := filepath.Join(cfg.ScanPath, ".deepguardignore")
	discoveryConfig := discovery.WalkerConfig{
		RootPath:       cfg.ScanPath,
		Languages:      cfg.Languages,
		IgnoreFile:     ignoreFile,
		FollowSymlinks: false,
	}

	result, err := discovery.DiscoverFiles(discoveryConfig)
	if err != nil {
		return fmt.Errorf("file discovery failed: %w", err)
	}

	log.Info().
		Str("component", "scanner").
		Int("total_files", result.TotalFiles).
		Int("test_files", result.TotalTestFiles).
		Int("skipped_files", result.SkippedFiles).
		Msg("File discovery completed")

	// Display file counts by language
	fmt.Printf("\nDiscovered %d files:\n", result.TotalFiles)
	for lang, count := range result.CountsByLanguage {
		fmt.Printf("  %s: %d files\n", lang, count)
	}
	fmt.Printf("  Test files: %d\n", result.TotalTestFiles)
	if result.SkippedFiles > 0 {
		fmt.Printf("  Skipped: %d files\n", result.SkippedFiles)
	}
	fmt.Printf("\n")

	if result.TotalFiles == 0 {
		fmt.Println("No files to scan. Exiting.")
		return nil
	}

	// Detect frameworks
	projectCtx, err := discovery.DetectFrameworks(cfg.ScanPath)
	if err != nil {
		log.Warn().
			Err(err).
			Str("component", "scanner").
			Msg("Framework detection failed, continuing without framework context")
		projectCtx = &discovery.ProjectContext{Frameworks: make(map[string][]string)}
	}

	// Display detected frameworks
	if len(projectCtx.Frameworks) > 0 {
		fmt.Printf("\nDetected frameworks:\n")
		for lang, frameworks := range projectCtx.Frameworks {
			fmt.Printf("  %s: %s\n", lang, strings.Join(frameworks, ", "))
		}
		fmt.Printf("\n")
	}

	// Initialize KB index
	indexManager := kb.NewIndexManager("", "")
	if err := indexManager.Initialize(); err != nil {
		return fmt.Errorf("failed to initialize KB index: %w", err)
	}
	defer indexManager.Close()

	// Initialize RAG retriever with caching
	retriever := rag.NewRetriever(indexManager, rag.RetrieverConfig{
		EnableCache: true,
	})

	// Initialize LLM client
	llmClient := llm.NewClient(cfg.OpenAIAPIKey, cfg.OpenAIModel)

	// Initialize orchestrator
	orchConfig := orchestrator.DefaultConfig()
	orchConfig.BudgetCap = cfg.BudgetCap
	orchConfig.FallbackModel = cfg.FallbackModel
	orc, err := orchestrator.NewOrchestrator(orchConfig, llmClient, cfg.OpenAIModel)
	if err != nil {
		return fmt.Errorf("failed to create orchestrator: %w", err)
	}
	orc.SetRetriever(retriever)

	// Initialize parser and chunker
	tsParser, err := parser.NewTreeSitterParser()
	if err != nil {
		return fmt.Errorf("failed to create parser: %w", err)
	}
	defer tsParser.Close()
	astChunker := chunker.NewASTChunker(0)

	// Parse and chunk all discovered files
	fmt.Printf("Parsing files...\n")
	var allChunks []chunker.CodeChunk
	chunksByFuncName := make(map[string]chunker.CodeChunk)
	parseErrors := 0

	for _, file := range result.Files {
		absPath := filepath.Join(cfg.ScanPath, file.Path)
		content, err := os.ReadFile(absPath)
		if err != nil {
			log.Warn().Err(err).Str("file", file.Path).Msg("failed to read file, skipping")
			parseErrors++
			continue
		}

		tree, err := tsParser.Parse(content, file.Language)
		if err != nil {
			log.Warn().Err(err).Str("file", file.Path).Msg("failed to parse file, skipping")
			parseErrors++
			continue
		}

		frameworks := projectCtx.Frameworks[file.Language]
		fileChunks, err := astChunker.ChunkFile(tree, content, absPath, file.Language, frameworks)
		tree.Close()
		if err != nil {
			log.Warn().Err(err).Str("file", file.Path).Msg("failed to chunk file, skipping")
			parseErrors++
			continue
		}

		for _, chunk := range fileChunks {
			allChunks = append(allChunks, chunk)
			chunksByFuncName[chunk.FunctionName] = chunk
		}
	}

	fmt.Printf("Extracted %d chunks from %d files", len(allChunks), result.TotalFiles-parseErrors)
	if parseErrors > 0 {
		fmt.Printf(" (%d files skipped due to parse errors)", parseErrors)
	}
	fmt.Printf("\n\n")

	if len(allChunks) == 0 {
		fmt.Println("No code chunks to analyze. Exiting.")
		return nil
	}

	// Run LLM analysis across all vulnerability types
	fmt.Printf("Running vulnerability analysis (this may take a while)...\n")
	startTime := time.Now()
	ctx := context.Background()

	typeFindings, analysisErr := orc.AnalyzeRepositoryAllTypes(ctx, allChunks)
	if analysisErr != nil && len(typeFindings) == 0 {
		return fmt.Errorf("analysis failed: %w", analysisErr)
	}
	if analysisErr != nil {
		log.Warn().Err(analysisErr).Msg("analysis completed with errors, partial results available")
	}

	// Convert types.Finding → report.Finding
	reportFindings := convertFindings(typeFindings)

	// Apply confidence threshold filtering
	filteredFindings, filterStats := reporting.FilterFindingsByConfidence(
		reportFindings, cfg.ConfidenceThreshold, log.Logger,
	)

	// Apply inline suppression filtering
	finalFindings, suppressStats := reporting.FilterSuppressedFindings(
		filteredFindings, chunksByFuncName, log.Logger,
	)

	// Flatten detected frameworks for metadata
	var allFrameworks []string
	seen := make(map[string]bool)
	for _, fws := range projectCtx.Frameworks {
		for _, fw := range fws {
			if !seen[fw] {
				allFrameworks = append(allFrameworks, fw)
				seen[fw] = true
			}
		}
	}

	// Get total cost from tracker
	_, _, _, totalCost, _ := llmClient.GetTracker().GetTotals()

	scanReport := report.ScanReport{
		ScanMetadata: report.ScanMetadata{
			Timestamp:           time.Now().UTC().Format(time.RFC3339),
			TargetPath:          cfg.ScanPath,
			Languages:           cfg.Languages,
			Frameworks:          allFrameworks,
			ModelUsed:           orc.GetFinalModel(),
			TotalCost:           totalCost,
			ScanDurationSeconds: int(time.Since(startTime).Seconds()),
			Filtering: &report.FilteringStats{
				Enabled:          filterStats.Enabled,
				ThresholdUsed:    filterStats.ThresholdUsed,
				TotalFindings:    filterStats.TotalFindings,
				FilteredFindings: filterStats.FilteredFindings,
				KeptFindings:     filterStats.KeptFindings,
			},
			Suppression: &report.SuppressionStats{
				TotalFindings:      suppressStats.TotalFindings,
				SuppressedFindings: suppressStats.SuppressedFindings,
				KeptFindings:       suppressStats.KeptFindings,
			},
		},
		Findings: finalFindings,
		Summary:  report.GenerateSummary(finalFindings),
	}

	outputPath, err := report.WriteReport(scanReport, cfg.OutputDir)
	if err != nil {
		return fmt.Errorf("failed to write report: %w", err)
	}

	duration := time.Since(startTime)
	fmt.Printf("\nScan complete!\n")
	fmt.Printf("  Findings:  %d (critical: %d, high: %d, medium: %d, low: %d)\n",
		len(finalFindings),
		scanReport.Summary.BySeverity["critical"],
		scanReport.Summary.BySeverity["high"],
		scanReport.Summary.BySeverity["medium"],
		scanReport.Summary.BySeverity["low"],
	)
	fmt.Printf("  Duration:  %s\n", duration.Round(time.Second))
	fmt.Printf("  Cost:      $%.4f\n", totalCost)
	fmt.Printf("  Report:    %s\n", outputPath)

	log.Info().
		Str("component", "scanner").
		Str("operation", "scan_complete").
		Int("findings", len(finalFindings)).
		Float64("cost", totalCost).
		Str("output", outputPath).
		Msg("Scan completed successfully")

	return nil
}

// convertFindings maps types.Finding (LLM output) to report.Finding (report schema).
func convertFindings(typeFindings []types.Finding) []report.Finding {
	findings := make([]report.Finding, 0, len(typeFindings))
	for i, f := range typeFindings {
		id := fmt.Sprintf("%d-%s-%d", i, f.Type, f.AbsoluteLine)
		if len(f.ChunkID) >= 8 {
			id = fmt.Sprintf("%s-%s-%d", f.ChunkID[:8], f.Type, f.AbsoluteLine)
		}
		findings = append(findings, report.Finding{
			ID:             id,
			Type:           f.Type,
			Severity:       f.Severity,
			Confidence:     f.Confidence,
			File:           f.FilePath,
			Line:           f.AbsoluteLine,
			FunctionName:   f.FunctionName,
			Message:        f.Message,
			Recommendation: f.Recommendation,
		})
	}
	return findings
}
