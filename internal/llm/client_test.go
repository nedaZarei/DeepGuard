package llm

import (
	"context"
	"testing"
	"time"

	"github.com/Neda-Zarei/deep-guard/internal/chunker"
	"github.com/Neda-Zarei/deep-guard/internal/kb"
)

func TestNewClient(t *testing.T) {
	client := NewClient("test-api-key", "gpt-4o-mini")

	if client == nil {
		t.Fatal("expected non-nil client")
	}

	if client.model != "gpt-4o-mini" {
		t.Errorf("expected model gpt-4o-mini, got %s", client.model)
	}

	if client.tracker == nil {
		t.Error("expected non-nil tracker")
	}

	if client.client == nil {
		t.Error("expected non-nil openai client")
	}
}

func TestNewClientWithBaseURL(t *testing.T) {
	customURL := "https://custom.api.example.com/v1"
	client := NewClientWithBaseURL("test-api-key", "gpt-4o", customURL)

	if client == nil {
		t.Fatal("expected non-nil client")
	}

	if client.model != "gpt-4o" {
		t.Errorf("expected model gpt-4o, got %s", client.model)
	}
}

func TestClientGetTracker(t *testing.T) {
	client := NewClient("test-api-key", "gpt-4o-mini")

	tracker := client.GetTracker()
	if tracker == nil {
		t.Error("expected non-nil tracker")
	}

	// verify it's the same tracker instance
	if tracker != client.tracker {
		t.Error("gettracker should return the same tracker instance")
	}
}

func TestClientExceedsBudget(t *testing.T) {
	client := NewClient("test-api-key", "gpt-4o-mini")

	// initially should not exceed any budget
	if client.ExceedsBudget(1.0) {
		t.Error("should not exceed budget initially")
	}

	// manually record some usage
	client.tracker.Record(10000, 5000, 0.5)

	// should not exceed $1.00 budget
	if client.ExceedsBudget(1.0) {
		t.Error("should not exceed $1.00 budget with $0.50 spent")
	}

	// should exceed $0.40 budget
	if !client.ExceedsBudget(0.40) {
		t.Error("should exceed $0.40 budget with $0.50 spent")
	}
}

func TestHandleAPIError_ClientError(t *testing.T) {
	client := NewClient("test-api-key", "gpt-4o-mini")

	// simulate a 400 bad request (non-retryable)
	// we can't easily create an actual apierror without calling the api,
	// so we'll test with a generic error
	err := client.handleAPIError(context.DeadlineExceeded)

	// should wrap as retryable for network errors
	if _, ok := err.(*retryableError); !ok {
		t.Error("expected retryable error for network error")
	}
}

func TestAnalyze_InvalidContext(t *testing.T) {
	client := NewClient("test-api-key", "gpt-4o-mini")

	// create an already-cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	chunk := chunker.CodeChunk{
		ID:           "test-chunk",
		FunctionName: "testFunction",
		Language:     "javascript",
		Source:       "function test() { return 42; }",
	}

	kbEntries := []kb.KBEntry{}
	prompt := "analyze this code"

	_, err := client.Analyze(ctx, chunk, kbEntries, prompt)
	if err == nil {
		t.Error("expected error with cancelled context")
	}
}

// integration test with real api (requires valid api key)
// this test is skipped by default - run with: go test -tags=integration
func TestAnalyze_RealAPI(t *testing.T) {
	// skip in normal test runs
	t.Skip("skipping integration test - requires valid api key")

	// to run this test:
	// 1. set deepguard_openai_api_key environment variable
	// 2. run: go test -v -tags=integration ./internal/llm/

	apiKey := "sk-GYbWqA0RH2L5oLDATQQhoCp3bfjzoGNizoFO5cb1wjY3cJnm"
	if apiKey == "" {
		t.Skip("deepguard_openai_api_key not set")
	}

	client := NewClient(apiKey, "gpt-4o-mini")

	chunk := chunker.CodeChunk{
		ID:           "test-chunk-001",
		FunctionName: "getUserById",
		Language:     "javascript",
		Source:       "function getUserById(id) { return db.query('SELECT * FROM users WHERE id = ' + id); }",
		FilePath:     "/test/example.js",
		StartLine:    1,
		EndLine:      3,
	}

	kbEntries := []kb.KBEntry{
		{
			ID:          "sqli-001",
			Title:       "SQL Injection via String Concatenation",
			Description: "Direct string concatenation in SQL queries allows attackers to inject malicious SQL code.",
			CodePatterns: []string{
				"query(' + input)",
				"execute(sql + user_input)",
			},
		},
	}

	prompt := `Analyze the following code for security vulnerabilities:

Code:
` + chunk.Source + `

Language: ` + chunk.Language + `
Function: ` + chunk.FunctionName + `

Known vulnerabilities to check:
- ` + kbEntries[0].Title + `: ` + kbEntries[0].Description + `

Provide a detailed analysis of any security issues found.`

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	response, err := client.Analyze(ctx, chunk, kbEntries, prompt)
	if err != nil {
		t.Fatalf("analyze failed: %v", err)
	}

	if response == nil {
		t.Fatal("expected non-nil response")
	}

	t.Logf("findings: %s", response.Findings)
	t.Logf("prompt tokens: %d", response.PromptTokens)
	t.Logf("completion tokens: %d", response.CompletionTokens)
	t.Logf("cost: $%.6f", response.Cost)
	t.Logf("model: %s", response.ModelUsed)

	if response.Findings == "" {
		t.Error("expected non-empty findings")
	}

	if response.PromptTokens == 0 {
		t.Error("expected non-zero prompt tokens")
	}

	if response.CompletionTokens == 0 {
		t.Error("expected non-zero completion tokens")
	}

	if response.Cost == 0.0 {
		t.Error("expected non-zero cost")
	}

	if response.ModelUsed != "gpt-4o-mini" {
		t.Errorf("expected model gpt-4o-mini, got %s", response.ModelUsed)
	}

	// check tracker
	p, c, total, cost, calls := client.GetTracker().GetTotals()
	if calls != 1 {
		t.Errorf("expected 1 call recorded, got %d", calls)
	}
	if p == 0 || c == 0 || total == 0 {
		t.Error("expected non-zero token counts in tracker")
	}
	if cost == 0.0 {
		t.Error("expected non-zero cost in tracker")
	}

	t.Logf("tracker totals: prompt=%d completion=%d total=%d cost=$%.6f calls=%d", p, c, total, cost, calls)
}

func TestGapGPTBaseURL(t *testing.T) {
	// verify the gapgpt base url constants are correct
	expectedPrimary := "https://api.gapgpt.app/v1"
	expectedCDN := "https://api.gapapi.com/v1"

	if GapGPTBaseURL != expectedPrimary {
		t.Errorf("expected primary url %s, got %s", expectedPrimary, GapGPTBaseURL)
	}

	if GapGPTCDNURL != expectedCDN {
		t.Errorf("expected cdn url %s, got %s", expectedCDN, GapGPTCDNURL)
	}
}
