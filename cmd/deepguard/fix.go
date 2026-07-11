package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Neda-Zarei/deep-guard/internal/config"
	"github.com/Neda-Zarei/deep-guard/internal/llm"
	"github.com/rs/zerolog/log"
	"github.com/sashabaranov/go-openai"
	"github.com/spf13/cobra"
)

var fixCmd = &cobra.Command{
	Use:   "fix",
	Short: "Apply AI-generated patches for vulnerabilities found in a scan report",
	Long: `Fix reads a Deep-Guard scan report (JSON) and, for each high or critical
finding, generates a concrete code patch and writes it to the output directory.

Each patch file is a unified-diff-style recommendation alongside a brief
explanation of the root cause and the fix applied.

The recommendation field in the scan report already contains fix advice;
this command turns that advice into actual corrected code you can review
and apply with: patch -p1 < fix-output/<file>.patch`,
	Example: `  deepguard fix --report reports/scan-2026.json --output ./fix-output
  deepguard fix --report reports/scan-2026.json --min-severity medium`,
	RunE: runFix,
}

func init() {
	rootCmd.AddCommand(fixCmd)
	fixCmd.Flags().StringP("report", "r", "", "path to scan report JSON (required)")
	fixCmd.MarkFlagRequired("report")
	fixCmd.Flags().StringP("output", "o", "./fix-output/", "output directory for patches")
	fixCmd.Flags().StringP("min-severity", "s", "high", "minimum severity to fix (low|medium|high|critical)")
}

type fixPatch struct {
	FindingType string `json:"finding_type"`
	File        string `json:"file"`
	Line        int    `json:"line"`
	Severity    string `json:"severity"`
	RootCause   string `json:"root_cause"`
	Explanation string `json:"explanation"`
	Patch       string `json:"patch"`
}

var severityRank = map[string]int{
	"low": 1, "medium": 2, "high": 3, "critical": 4,
}

func runFix(cmd *cobra.Command, args []string) error {
	reportPath, _ := cmd.Flags().GetString("report")
	outputDir, _ := cmd.Flags().GetString("output")
	minSev, _ := cmd.Flags().GetString("min-severity")

	cfg, err := config.LoadConfig()
	if err != nil {
		return fmt.Errorf("configuration error: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("configuration validation failed: %w", err)
	}

	baseURL := os.Getenv("DEEPGUARD_OPENAI_BASE_URL")
	if baseURL == "" {
		baseURL = llm.OpenAIBaseURL
	}

	raw, err := os.ReadFile(reportPath)
	if err != nil {
		return fmt.Errorf("cannot read report: %w", err)
	}
	var report struct {
		Findings []struct {
			Type           string  `json:"type"`
			File           string  `json:"file"`
			Line           int     `json:"line"`
			Severity       string  `json:"severity"`
			Description    string  `json:"description"`
			Recommendation string  `json:"recommendation"`
			Confidence     float64 `json:"confidence"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(raw, &report); err != nil {
		return fmt.Errorf("invalid report JSON: %w", err)
	}

	oaiCfg := openai.DefaultConfig(cfg.OpenAIAPIKey)
	oaiCfg.BaseURL = baseURL
	oaiClient := openai.NewClientWithConfig(oaiCfg)

	minRank := severityRank[strings.ToLower(minSev)]
	if minRank == 0 {
		minRank = 3
	}

	fmt.Printf("Deep-Guard Fix\n")
	fmt.Printf("Report:   %s\n", reportPath)
	fmt.Printf("Output:   %s\n", outputDir)
	fmt.Printf("Min sev:  %s\n\n", minSev)

	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output dir: %w", err)
	}

	var patches []fixPatch
	totalCost := 0.0

	for _, f := range report.Findings {
		if severityRank[strings.ToLower(f.Severity)] < minRank {
			continue
		}

		srcContent := ""
		if f.File != "" {
			b, err := os.ReadFile(f.File)
			if err == nil {
				srcContent = contextWindow(string(b), f.Line, 15)
			}
		}

		patch, cost, err := generateFix(oaiClient, cfg.OpenAIModel, f.Type, f.File, f.Line,
			f.Description, f.Recommendation, srcContent)
		if err != nil {
			log.Warn().Str("file", f.File).Int("line", f.Line).Err(err).Msg("fix generation failed")
			continue
		}
		totalCost += cost

		p := fixPatch{
			FindingType: f.Type,
			File:        f.File,
			Line:        f.Line,
			Severity:    f.Severity,
			RootCause:   patch.RootCause,
			Explanation: patch.Explanation,
			Patch:       patch.Patch,
		}
		patches = append(patches, p)
		fmt.Printf("  ✓ %s:%d [%s] — %s\n", f.File, f.Line, f.Severity, f.Type)

		writePatchFile(outputDir, p)
	}

	summaryPath := filepath.Join(outputDir, fmt.Sprintf("fix-summary-%s.json",
		time.Now().Format("20060102-150405")))
	summaryData, _ := json.MarshalIndent(map[string]any{
		"generated_at":   time.Now().UTC().Format(time.RFC3339),
		"report":         reportPath,
		"patches_count":  len(patches),
		"total_cost_usd": totalCost,
		"patches":        patches,
	}, "", "  ")
	os.WriteFile(summaryPath, summaryData, 0644)

	fmt.Printf("\n✓ Generated %d patches\n", len(patches))
	fmt.Printf("  Cost:    $%.4f\n", totalCost)
	fmt.Printf("  Summary: %s\n", summaryPath)
	fmt.Printf("\nApply a patch: patch -p1 < %s/<file>.patch\n", outputDir)
	return nil
}

type fixResult struct {
	RootCause   string `json:"root_cause"`
	Explanation string `json:"explanation"`
	Patch       string `json:"patch"`
}

func generateFix(client *openai.Client, model, vulnType, filePath string, line int,
	description, recommendation, srcContext string) (*fixResult, float64, error) {

	contextSection := ""
	if srcContext != "" {
		contextSection = fmt.Sprintf("\nRelevant source context (lines ±15 around line %d):\n```\n%s\n```\n", line, srcContext)
	}

	prompt := fmt.Sprintf(
		`You are a secure code reviewer. A vulnerability was found:

Type:           %s
File:           %s
Line:           %d
Description:    %s
Recommendation: %s
%s
Generate a fix. Return ONLY valid JSON:
{
  "root_cause":   "<one sentence: why this is vulnerable>",
  "explanation":  "<2-3 sentences: what the patch does and why it is secure>",
  "patch":        "<unified diff patch (--- a/file +++ b/file @@ ... lines) showing the fix, or the corrected code block if a full diff is not possible>"
}`,
		vulnType, filePath, line, description, recommendation, contextSection)

	resp, err := client.CreateChatCompletion(context.Background(), openai.ChatCompletionRequest{
		Model: model,
		Messages: []openai.ChatCompletionMessage{
			{Role: openai.ChatMessageRoleSystem, Content: "You are a security engineer. Respond only with valid JSON."},
			{Role: openai.ChatMessageRoleUser, Content: prompt},
		},
		Temperature:    0,
		ResponseFormat: &openai.ChatCompletionResponseFormat{Type: openai.ChatCompletionResponseFormatTypeJSONObject},
	})
	if err != nil {
		return nil, 0, err
	}

	cost := float64(resp.Usage.PromptTokens)*0.00000015 + float64(resp.Usage.CompletionTokens)*0.0000006
	var result fixResult
	if err := json.Unmarshal([]byte(resp.Choices[0].Message.Content), &result); err != nil {
		return &fixResult{Patch: strings.TrimSpace(resp.Choices[0].Message.Content)}, cost, nil
	}
	return &result, cost, nil
}

func writePatchFile(outRoot string, p fixPatch) {
	safeFile := strings.ReplaceAll(strings.ReplaceAll(p.File, "/", "_"), ".", "_")
	name := fmt.Sprintf("%s_line%d_%s.patch", safeFile, p.Line, p.FindingType)
	outPath := filepath.Join(outRoot, name)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("# Deep-Guard Fix — %s\n", time.Now().Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("# File: %s  Line: %d  Severity: %s\n", p.File, p.Line, p.Severity))
	sb.WriteString(fmt.Sprintf("# Type: %s\n\n", p.FindingType))
	sb.WriteString("## Root Cause\n")
	sb.WriteString(p.RootCause + "\n\n")
	sb.WriteString("## Explanation\n")
	sb.WriteString(p.Explanation + "\n\n")
	sb.WriteString("## Patch\n")
	sb.WriteString(p.Patch + "\n")

	os.WriteFile(outPath, []byte(sb.String()), 0644)
}

func contextWindow(src string, line, radius int) string {
	lines := strings.Split(src, "\n")
	start := line - 1 - radius
	end := line - 1 + radius + 1
	if start < 0 {
		start = 0
	}
	if end > len(lines) {
		end = len(lines)
	}
	var sb strings.Builder
	for i := start; i < end; i++ {
		marker := "  "
		if i == line-1 {
			marker = ">>"
		}
		fmt.Fprintf(&sb, "%s %4d: %s\n", marker, i+1, lines[i])
	}
	return sb.String()
}
