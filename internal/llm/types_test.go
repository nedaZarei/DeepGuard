package llm

import (
	"testing"
)

func TestCalculateCost(t *testing.T) {
	tests := []struct {
		name             string
		model            string
		promptTokens     int
		completionTokens int
		expectedCost     float64
	}{
		{
			name:             "gpt-4o small request",
			model:            "gpt-4o",
			promptTokens:     1000,
			completionTokens: 500,
			expectedCost:     0.0025 + 0.005, // (1000/1M)*2.5 + (500/1M)*10
		},
		{
			name:             "gpt-4o-mini small request",
			model:            "gpt-4o-mini",
			promptTokens:     1000,
			completionTokens: 500,
			expectedCost:     0.00015 + 0.0003, // (1000/1M)*0.15 + (500/1M)*0.6
		},
		{
			name:             "gpt-4o large request",
			model:            "gpt-4o",
			promptTokens:     100000,
			completionTokens: 50000,
			expectedCost:     0.25 + 0.5, // (100k/1M)*2.5 + (50k/1M)*10
		},
		{
			name:             "gpt-4o-mini large request",
			model:            "gpt-4o-mini",
			promptTokens:     100000,
			completionTokens: 50000,
			expectedCost:     0.015 + 0.03, // (100k/1M)*0.15 + (50k/1M)*0.6
		},
		{
			name:             "unknown model defaults to gpt-4o-mini",
			model:            "unknown-model",
			promptTokens:     1000,
			completionTokens: 500,
			expectedCost:     0.00015 + 0.0003,
		},
		{
			name:             "zero tokens",
			model:            "gpt-4o",
			promptTokens:     0,
			completionTokens: 0,
			expectedCost:     0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cost := calculateCost(tt.model, tt.promptTokens, tt.completionTokens)

			// allow small floating point error (0.0001)
			diff := cost - tt.expectedCost
			if diff < 0 {
				diff = -diff
			}
			if diff > 0.0001 {
				t.Errorf("expected cost %.6f, got %.6f", tt.expectedCost, cost)
			}
		})
	}
}

func TestResponseStruct(t *testing.T) {
	// test that response struct can be created and fields are accessible
	resp := Response{
		Findings:         "vulnerability found: sql injection",
		PromptTokens:     1000,
		CompletionTokens: 500,
		Cost:             0.0075,
		ModelUsed:        "gpt-4o",
	}

	if resp.Findings != "vulnerability found: sql injection" {
		t.Errorf("findings mismatch")
	}
	if resp.PromptTokens != 1000 {
		t.Errorf("prompt tokens mismatch")
	}
	if resp.CompletionTokens != 500 {
		t.Errorf("completion tokens mismatch")
	}
	if resp.Cost != 0.0075 {
		t.Errorf("cost mismatch")
	}
	if resp.ModelUsed != "gpt-4o" {
		t.Errorf("model used mismatch")
	}
}
