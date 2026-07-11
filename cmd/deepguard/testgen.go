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

var testgenCmd = &cobra.Command{
	Use:   "testgen",
	Short: "Generate security-focused unit tests for source code functions",
	Long: `Testgen analyzes each function in your codebase and produces unit tests
that cover both happy-path and adversarial/security edge cases.

Generated tests use the idiomatic testing framework for each language:
  JavaScript/TypeScript → Jest
  Python               → pytest
  Java                 → JUnit 5
  C/C++                → a standalone main() with assert()`,
	Example: `  deepguard testgen --path ./src --output ./tests/generated
  deepguard testgen --path ./api --languages js,ts`,
	RunE: runTestgen,
}

func init() {
	rootCmd.AddCommand(testgenCmd)
	testgenCmd.Flags().StringP("path", "p", "", "target directory (required)")
	testgenCmd.MarkFlagRequired("path")
	testgenCmd.Flags().StringP("output", "o", "./testgen-output/", "output directory for generated tests")
	testgenCmd.Flags().StringSliceP("languages", "l",
		[]string{"js", "ts", "python", "java", "c", "cpp"}, "languages to generate tests for")
}

type testgenFileResult struct {
	File  string         `json:"file"`
	Tests []funcTestItem `json:"tests"`
}

type funcTestItem struct {
	FunctionName string `json:"function_name"`
	StartLine    int    `json:"start_line"`
	TestCode     string `json:"test_code"`
	Framework    string `json:"framework"`
}

var testFrameworks = map[string]string{
	"javascript": "Jest",
	"typescript": "Jest (TypeScript)",
	"python":     "pytest",
	"java":       "JUnit 5",
	"c":          "standalone C (assert.h)",
	"cpp":        "standalone C++ (assert.h / cassert)",
}

var testFileExtensions = map[string]string{
	"javascript": ".test.js",
	"typescript": ".test.ts",
	"python":     "_test.py",
	"java":       "Test.java",
	"c":          "_test.c",
	"cpp":        "_test.cpp",
}

func runTestgen(cmd *cobra.Command, args []string) error {
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

	fmt.Printf("Deep-Guard Test Generator\n")
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

	var allResults []testgenFileResult
	totalTests := 0
	totalCost := 0.0

	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output dir: %w", err)
	}

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

		result := testgenFileResult{File: file.Path}
		for _, chunk := range chunks {
			testCode, cost, err := generateTests(oaiClient, cfg.OpenAIModel, chunk, file.Language)
			if err != nil {
				log.Warn().Str("func", chunk.FunctionName).Err(err).Msg("test generation failed")
				continue
			}
			totalCost += cost
			totalTests++
			framework := testFrameworks[file.Language]
			result.Tests = append(result.Tests, funcTestItem{
				FunctionName: chunk.FunctionName,
				StartLine:    chunk.StartLine,
				TestCode:     testCode,
				Framework:    framework,
			})
		}

		if len(result.Tests) > 0 {
			allResults = append(allResults, result)
			writeTestFile(outputDir, result, file.Language)
		}
	}

	// Write JSON report
	reportPath := filepath.Join(outputDir, fmt.Sprintf("testgen-report-%s.json",
		time.Now().Format("20060102-150405")))
	reportData, _ := json.MarshalIndent(map[string]any{
		"generated_at":   time.Now().UTC().Format(time.RFC3339),
		"target":         scanPath,
		"total_tests":    totalTests,
		"total_cost_usd": totalCost,
		"files":          allResults,
	}, "", "  ")
	os.WriteFile(reportPath, reportData, 0644)

	fmt.Printf("\n✓ Generated %d tests across %d files\n", totalTests, len(allResults))
	fmt.Printf("  Cost:   $%.4f\n", totalCost)
	fmt.Printf("  Output: %s\n", outputDir)
	fmt.Printf("  Report: %s\n", reportPath)
	return nil
}

func generateTests(client *openai.Client, model string, chunk chunker.CodeChunk, language string) (string, float64, error) {
	framework := testFrameworks[language]
	if framework == "" {
		framework = "standard unit tests"
	}
	numbered := numberedLines(chunk.Source, chunk.StartLine)
	prompt := fmt.Sprintf(
		`Generate %s tests for the function below.

Return ONLY valid JSON: {"test_code": "<complete test file or test block>"}

Requirements:
1. Cover the happy path (valid inputs, expected outputs)
2. Cover at least 3 security/adversarial edge cases:
   - SQL injection payloads if the function queries a database
   - Path traversal strings if the function handles file paths
   - Oversized or null inputs
   - Integer boundary values (0, -1, MAX_INT) if arithmetic is involved
3. Use correct %s syntax and imports
4. Tests must be self-contained and runnable with mocked dependencies
5. Do NOT include the original source function in the output

File: %s | Function: %s (lines %d–%d)

%s`,
		framework, framework,
		chunk.FilePath, chunk.FunctionName, chunk.StartLine, chunk.EndLine,
		numbered)

	resp, err := client.CreateChatCompletion(context.Background(), openai.ChatCompletionRequest{
		Model: model,
		Messages: []openai.ChatCompletionMessage{
			{Role: openai.ChatMessageRoleSystem, Content: "You are a security-focused test engineer. Respond only with valid JSON."},
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
		TestCode string `json:"test_code"`
	}
	if err := json.Unmarshal([]byte(resp.Choices[0].Message.Content), &result); err != nil {
		return strings.TrimSpace(resp.Choices[0].Message.Content), cost, nil
	}
	return result.TestCode, cost, nil
}

func writeTestFile(outRoot string, result testgenFileResult, language string) {
	ext := testFileExtensions[language]
	if ext == "" {
		ext = ".test.txt"
	}
	base := strings.TrimSuffix(filepath.Base(result.File), filepath.Ext(result.File))
	dir := filepath.Dir(result.File)
	outPath := filepath.Join(outRoot, dir, base+ext)
	os.MkdirAll(filepath.Dir(outPath), 0755)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("// Auto-generated by deepguard testgen — %s\n", time.Now().Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("// Source: %s\n\n", result.File))
	for _, t := range result.Tests {
		sb.WriteString(fmt.Sprintf("// --- %s (line %d) ---\n", t.FunctionName, t.StartLine))
		sb.WriteString(t.TestCode)
		sb.WriteString("\n\n")
	}
	os.WriteFile(outPath, []byte(sb.String()), 0644)
}
