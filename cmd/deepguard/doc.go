package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Neda-Zarei/deep-guard/internal/chunker"
	"github.com/Neda-Zarei/deep-guard/internal/config"
	"github.com/Neda-Zarei/deep-guard/internal/discovery"
	"github.com/Neda-Zarei/deep-guard/internal/llm"
	"github.com/Neda-Zarei/deep-guard/internal/parser"
	"github.com/rs/zerolog/log"
	"github.com/sashabaranov/go-openai"
	"github.com/spf13/cobra"
)

var docCmd = &cobra.Command{
	Use:   "doc",
	Short: "Generate documentation comments for source code functions",
	Long: `Doc analyzes source code functions and generates language-appropriate
documentation comments (JSDoc, PyDoc, Javadoc, Doxygen) using AI.

Output files are written to the output directory, preserving the original
directory structure with docstrings injected before each function.`,
	Example: `  deepguard doc --path ./my-project --output ./doc-output
  deepguard doc --path ./src --languages js,ts,python`,
	RunE: runDoc,
}

func init() {
	rootCmd.AddCommand(docCmd)
	docCmd.Flags().StringP("path", "p", "", "target directory to document (required)")
	docCmd.MarkFlagRequired("path")
	docCmd.Flags().StringP("output", "o", "./doc-output/", "output directory for documented files")
	docCmd.Flags().StringSliceP("languages", "l",
		[]string{"js", "ts", "python", "java", "c", "cpp"}, "languages to document")
}

type docFileResult struct {
	File      string        `json:"file"`
	Functions []funcDocItem `json:"functions"`
}

type funcDocItem struct {
	Name      string `json:"name"`
	StartLine int    `json:"start_line"`
	Docstring string `json:"docstring"`
}

func runDoc(cmd *cobra.Command, args []string) error {
	scanPath, _ := cmd.Flags().GetString("path")
	outputDir, _ := cmd.Flags().GetString("output")
	languages, _ := cmd.Flags().GetStringSlice("languages")

	cfg, err := config.LoadConfig()
	if err != nil {
		return fmt.Errorf("configuration error: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("configuration validation failed: %w", err)
	}

	baseURL := os.Getenv("DEEPGUARD_OPENAI_BASE_URL")
	if baseURL == "" {
		baseURL = llm.GapGPTBaseURL
	}

	fmt.Printf("Deep-Guard Doc Generator\n")
	fmt.Printf("Target:  %s\n", scanPath)
	fmt.Printf("Output:  %s\n", outputDir)
	fmt.Printf("Model:   %s\n\n", cfg.OpenAIModel)

	disc, err := discovery.DiscoverFiles(discovery.WalkerConfig{
		RootPath:  scanPath,
		Languages: languages,
	})
	if err != nil {
		return fmt.Errorf("file discovery failed: %w", err)
	}
	fmt.Printf("Discovered %d files\n\n", disc.TotalFiles)

	tsParser, err := parser.NewTreeSitterParser()
	if err != nil {
		return fmt.Errorf("parser init failed: %w", err)
	}
	defer tsParser.Close()

	astChunker := chunker.NewASTChunker(4096)

	oaiCfg := openai.DefaultConfig(cfg.OpenAIAPIKey)
	oaiCfg.BaseURL = baseURL
	oaiClient := openai.NewClientWithConfig(oaiCfg)

	var allResults []docFileResult
	totalFuncs := 0
	totalCost := 0.0

	for _, file := range disc.Files {
		fullPath := filepath.Join(scanPath, file.Path)
		content, err := os.ReadFile(fullPath)
		if err != nil {
			log.Warn().Str("file", file.Path).Err(err).Msg("skipping unreadable file")
			continue
		}
		tree, err := tsParser.Parse(content, file.Language)
		if err != nil {
			log.Warn().Str("file", file.Path).Err(err).Msg("parse error, skipping")
			continue
		}
		chunks, _ := astChunker.ChunkFile(tree, content, fullPath, file.Language, nil)
		tree.Close()

		if len(chunks) == 0 {
			continue
		}
		fmt.Printf("  %s — %d functions\n", file.Path, len(chunks))

		result := docFileResult{File: file.Path}
		for _, chunk := range chunks {
			doc, cost, err := generateDocstring(oaiClient, cfg.OpenAIModel, chunk, file.Language)
			if err != nil {
				log.Warn().Str("func", chunk.FunctionName).Err(err).Msg("doc generation failed")
				continue
			}
			totalCost += cost
			totalFuncs++
			result.Functions = append(result.Functions, funcDocItem{
				Name:      chunk.FunctionName,
				StartLine: chunk.StartLine,
				Docstring: doc,
			})
		}
		allResults = append(allResults, result)
	}

	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output dir: %w", err)
	}

	// Write JSON report
	reportPath := filepath.Join(outputDir, fmt.Sprintf("doc-report-%s.json",
		time.Now().Format("20060102-150405")))
	reportData, _ := json.MarshalIndent(map[string]any{
		"generated_at":    time.Now().UTC().Format(time.RFC3339),
		"target":          scanPath,
		"total_functions": totalFuncs,
		"total_cost_usd":  totalCost,
		"files":           allResults,
	}, "", "  ")
	os.WriteFile(reportPath, reportData, 0644)

	// Write annotated source files
	writeAnnotatedFiles(scanPath, outputDir, allResults)

	fmt.Printf("\n✓ Documented %d functions across %d files\n", totalFuncs, len(allResults))
	fmt.Printf("  Cost:   $%.4f\n", totalCost)
	fmt.Printf("  Report: %s\n", reportPath)
	return nil
}

var docStyles = map[string]string{
	"javascript": "JSDoc",
	"typescript": "JSDoc with TypeScript types",
	"python":     "Google-style Python docstring",
	"java":       "Javadoc",
	"c":          "Doxygen",
	"cpp":        "Doxygen",
}

func generateDocstring(client *openai.Client, model string, chunk chunker.CodeChunk, language string) (string, float64, error) {
	style := docStyles[language]
	if style == "" {
		style = "standard documentation comment"
	}
	numbered := numberedLines(chunk.Source, chunk.StartLine)
	prompt := fmt.Sprintf(
		`Generate a %s comment for the function below.

Return ONLY valid JSON: {"docstring": "<complete comment using correct %s syntax>"}

Rules:
- Correct comment delimiters for %s (/** */ for JSDoc/Javadoc/Doxygen, # for Python)
- Document: purpose, each parameter (@param/@arg/Args:), return value (@returns/Returns:)
- Max 10 lines; do NOT include the function source in the docstring

File: %s | Function: %s (lines %d-%d)

%s`,
		style, style, language,
		chunk.FilePath, chunk.FunctionName, chunk.StartLine, chunk.EndLine,
		numbered)

	resp, err := client.CreateChatCompletion(context.Background(), openai.ChatCompletionRequest{
		Model: model,
		Messages: []openai.ChatCompletionMessage{
			{Role: openai.ChatMessageRoleSystem, Content: "You are a technical documentation expert. Respond only with valid JSON."},
			{Role: openai.ChatMessageRoleUser, Content: prompt},
		},
		Temperature:    0,
		ResponseFormat: &openai.ChatCompletionResponseFormat{Type: openai.ChatCompletionResponseFormatTypeJSONObject},
	})
	if err != nil {
		return "", 0, err
	}

	cost := float64(resp.Usage.PromptTokens)*0.00000015 + float64(resp.Usage.CompletionTokens)*0.0000006
	var result struct {
		Docstring string `json:"docstring"`
	}
	if err := json.Unmarshal([]byte(resp.Choices[0].Message.Content), &result); err != nil {
		return strings.TrimSpace(resp.Choices[0].Message.Content), cost, nil
	}
	return result.Docstring, cost, nil
}

func writeAnnotatedFiles(srcRoot, outRoot string, results []docFileResult) {
	for _, r := range results {
		srcPath := filepath.Join(srcRoot, r.File)
		content, err := os.ReadFile(srcPath)
		if err != nil {
			continue
		}
		lines := strings.Split(string(content), "\n")

		// Insert in reverse order to preserve line numbers
		for i := len(r.Functions) - 1; i >= 0; i-- {
			fn := r.Functions[i]
			if fn.Docstring == "" {
				continue
			}
			insertAt := fn.StartLine - 1 // 0-indexed
			if insertAt < 0 || insertAt > len(lines) {
				continue
			}
			docLines := strings.Split(fn.Docstring, "\n")
			updated := make([]string, 0, len(lines)+len(docLines))
			updated = append(updated, lines[:insertAt]...)
			updated = append(updated, docLines...)
			updated = append(updated, lines[insertAt:]...)
			lines = updated
		}

		outPath := filepath.Join(outRoot, r.File)
		os.MkdirAll(filepath.Dir(outPath), 0755)
		os.WriteFile(outPath, []byte(strings.Join(lines, "\n")), 0644)
	}
}

func numberedLines(source string, startLine int) string {
	lines := strings.Split(source, "\n")
	sb := &strings.Builder{}
	for i, line := range lines {
		fmt.Fprintf(sb, "%4d: %s\n", startLine+i, line)
	}
	return sb.String()
}
