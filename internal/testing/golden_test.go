package testing

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Neda-Zarei/deep-guard/internal/report"
)

// TestJSTSSQLiGolden is a golden test that validates SQLi detection against expected findings
func TestJSTSSQLiGolden(t *testing.T) {
	// Skip in short mode or if explicitly disabled
	if testing.Short() {
		t.Skip("Skipping golden test in short mode")
	}

	if os.Getenv("SKIP_GOLDEN_TESTS") == "1" {
		t.Skip("Golden tests disabled via SKIP_GOLDEN_TESTS=1")
	}

	// Load golden file
	goldenPath := filepath.Join("..", "..", "test-samples", "js-ts-sqli", "expected-findings.json")
	golden, err := LoadGoldenFile(goldenPath)
	if err != nil {
		t.Fatalf("Failed to load golden file: %v", err)
	}

	t.Logf("Loaded golden file with %d expected findings", len(golden.Expected))

	// Get scan results: live scan when API key is available, otherwise cached results
	reportPath := filepath.Join("..", "..", "test-samples", "js-ts-sqli", "scan-results.json")
	scanReport := getScanReport(t, golden.ScanMetadata.TargetPath, reportPath)

	// Use ±10 line tolerance: LLM reports query-execution lines, ground truth marks
	// input-capture lines for the same vulnerability instance.
	result := CompareResults(golden, scanReport, 10)

	// Print detailed comparison
	t.Log(FormatComparisonResult(result))

	// Assert no false negatives (all expected findings detected)
	if len(result.Missing) > 0 {
		t.Errorf("False negatives detected: %d expected findings not detected", len(result.Missing))
		for _, missing := range result.Missing {
			t.Errorf("  Missing: %s:%d (%s)", missing.File, missing.Line, missing.Pattern)
		}
	}

	// Assert confidence thresholds met
	if len(result.ConfidenceMismatches) > 0 {
		t.Errorf("Confidence threshold failures: %d findings below minimum confidence", len(result.ConfidenceMismatches))
		for _, mismatch := range result.ConfidenceMismatches {
			t.Errorf("  Low confidence: %s:%d (expected >= %.2f, got %.2f)",
				mismatch.Expected.File, mismatch.Expected.Line,
				mismatch.ExpectedConf, mismatch.ActualConf)
		}
	}

	// Warn about unexpected high/critical findings (possible false positives)
	if len(result.Extra) > 0 {
		t.Logf("Warning: %d unexpected high/critical severity findings detected", len(result.Extra))
		for _, extra := range result.Extra {
			t.Logf("  Unexpected: %s:%d (%s, %s, %.2f confidence)",
				extra.File, extra.Line, extra.Type, extra.Severity, extra.Confidence)
		}
	}

	// Overall success
	if !result.Success {
		t.Errorf("Golden test failed: not all expected findings were detected with sufficient confidence")
	} else {
		t.Logf("✅ Golden test passed: all %d expected findings detected", result.Matched)
	}
}

// getScanReport returns scan results, preferring a live scan when OPENAI_API_KEY is set,
// otherwise loading from a previously cached scan-results.json.
func getScanReport(t *testing.T, targetPath, reportPath string) report.ScanReport {
	t.Helper()

	// Run live scan when an API key is available.
	// Accept either DEEPGUARD_OPENAI_API_KEY (what the binary reads) or OPENAI_API_KEY (common alias).
	if os.Getenv("DEEPGUARD_OPENAI_API_KEY") != "" || os.Getenv("OPENAI_API_KEY") != "" {
		t.Log("API key found — running live scan...")
		sr, err := runScan(t, targetPath)
		if err == nil {
			t.Logf("Live scan complete: %d findings (cost $%.4f)", len(sr.Findings), sr.ScanMetadata.TotalCost)
			// Only cache when LLM calls actually succeeded (cost > 0 means API was reached).
			// A $0 result with 0 findings means every worker hit an auth/network error and
			// stopped silently — don't pollute the cache with a bad baseline.
			if sr.ScanMetadata.TotalCost > 0 {
				if data, jerr := json.MarshalIndent(sr, "", "  "); jerr == nil {
					if werr := os.WriteFile(reportPath, data, 0644); werr != nil {
						t.Logf("Warning: could not cache scan results: %v", werr)
					} else {
						t.Logf("Cached scan results to %s", reportPath)
					}
				}
			} else {
				t.Log("Scan cost $0 — LLM calls did not succeed. Check DEEPGUARD_OPENAI_API_KEY and the API endpoint in internal/llm/client.go.")
			}
			return sr
		}
		t.Logf("Live scan failed (%v) — falling back to cached results", err)
	}

	// Load previously cached results
	if data, err := os.ReadFile(reportPath); err == nil {
		var sr report.ScanReport
		if err := json.Unmarshal(data, &sr); err == nil {
			t.Logf("Using cached scan results from %s (%d findings)", reportPath, len(sr.Findings))
			return sr
		}
	}

	t.Log("No scan results available (set DEEPGUARD_OPENAI_API_KEY or OPENAI_API_KEY to run a live scan) — using empty report")
	return report.ScanReport{
		ScanMetadata: report.ScanMetadata{
			TargetPath: targetPath,
			Languages:  []string{"javascript", "typescript"},
		},
		Findings: []report.Finding{},
		Summary: report.Summary{
			TotalFindings: 0,
			BySeverity:    make(map[string]int),
			ByType:        make(map[string]int),
		},
	}
}

// runScan executes the deepguard binary against targetPath and returns the parsed report.
// It builds the binary first if it is not already present at the repo root.
func runScan(t *testing.T, targetPath string) (report.ScanReport, error) {
	t.Helper()
	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		return report.ScanReport{}, fmt.Errorf("resolve repo root: %w", err)
	}

	// Allow overriding the binary path via env (useful in CI)
	binary := os.Getenv("DEEPGUARD_BINARY")
	if binary == "" {
		binary = filepath.Join(repoRoot, "deepguard")
	}

	// Build if missing
	if _, serr := os.Stat(binary); os.IsNotExist(serr) {
		buildCmd := exec.Command("go", "build", "-o", binary, "./cmd/deepguard/...")
		buildCmd.Dir = repoRoot
		if out, berr := buildCmd.CombinedOutput(); berr != nil {
			return report.ScanReport{}, fmt.Errorf("build failed: %w\n%s", berr, out)
		}
	}

	// Resolve the target path relative to the repo root
	absTarget := targetPath
	if !filepath.IsAbs(targetPath) {
		absTarget = filepath.Join(repoRoot, targetPath)
	}

	// Create a temp output directory
	tmpDir, err := os.MkdirTemp("", "deepguard-golden-*")
	if err != nil {
		return report.ScanReport{}, fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	cmd := exec.Command(binary,
		"scan",
		"--path", absTarget,
		"--output", tmpDir,
		"--confidence-threshold", "0.5",
		"--verbose",
	)
	cmd.Dir = repoRoot

	// Inherit the full environment. If only OPENAI_API_KEY is set (not the DEEPGUARD_ prefixed
	// form), add the translation so the binary's config loader picks it up.
	env := os.Environ()
	if os.Getenv("DEEPGUARD_OPENAI_API_KEY") == "" {
		if key := os.Getenv("OPENAI_API_KEY"); key != "" {
			env = append(env, "DEEPGUARD_OPENAI_API_KEY="+key)
		}
	}
	cmd.Env = env

	out, err := cmd.CombinedOutput()
	// Always log subprocess output so LLM errors / worker failures are visible in test output
	if len(out) > 0 {
		t.Logf("scan output:\n%s", out)
	}
	if err != nil {
		return report.ScanReport{}, fmt.Errorf("scan failed: %w", err)
	}

	// Find the generated JSON report
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		return report.ScanReport{}, fmt.Errorf("read output dir: %w", err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".json") {
			data, rerr := os.ReadFile(filepath.Join(tmpDir, e.Name()))
			if rerr != nil {
				continue
			}
			var sr report.ScanReport
			if jerr := json.Unmarshal(data, &sr); jerr == nil {
				return sr, nil
			}
		}
	}

	return report.ScanReport{}, fmt.Errorf("no valid JSON report found in %s", tmpDir)
}
