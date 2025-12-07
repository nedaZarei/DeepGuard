package llm

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Neda-Zarei/deep-guard/pkg/types"
	"github.com/rs/zerolog/log"
)

// APIResponse represents the structured JSON response from the LLM
type APIResponse struct {
	Findings []types.Finding `json:"findings"`
}

// ParseResponse parses and validates a JSON response from the LLM API
func ParseResponse(rawResponse string) (*APIResponse, error) {
	// Trim whitespace
	rawResponse = strings.TrimSpace(rawResponse)

	if rawResponse == "" {
		return nil, fmt.Errorf("empty response from API")
	}

	// Attempt to parse JSON
	var response APIResponse
	if err := json.Unmarshal([]byte(rawResponse), &response); err != nil {
		log.Debug().
			Err(err).
			Str("raw_response", truncateForLog(rawResponse, 500)).
			Msg("failed to parse JSON response")
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}

	// Validate the parsed response
	if err := ValidateAPIResponse(&response); err != nil {
		log.Debug().
			Err(err).
			Str("raw_response", truncateForLog(rawResponse, 500)).
			Msg("response validation failed")
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	return &response, nil
}

// ParseResponseWithRetry attempts to parse a response, and if it fails, it can signal a retry
// Returns: (response, shouldRetry, error)
func ParseResponseWithRetry(rawResponse string, attemptNumber int) (*APIResponse, bool, error) {
	response, err := ParseResponse(rawResponse)

	if err == nil {
		// Success
		return response, false, nil
	}

	// First attempt failed - should retry with stricter prompt
	if attemptNumber == 1 {
		log.Warn().
			Err(err).
			Str("raw_response", truncateForLog(rawResponse, 500)).
			Msg("first parse attempt failed, will retry with stricter prompt")
		return nil, true, err
	}

	// Second attempt failed - give up
	log.Error().
		Err(err).
		Str("raw_response", truncateForLog(rawResponse, 500)).
		Msg("second parse attempt failed, skipping chunk")
	return nil, false, err
}

// CreateStricterPrompt wraps the original prompt with additional emphasis on JSON-only output
func CreateStricterPrompt(originalPrompt string) string {
	prefix := `CRITICAL INSTRUCTION: You MUST respond with ONLY valid JSON. No explanations, no markdown code blocks, no additional text.

Your response must start with { and end with }. Nothing else.

If you include ANY text outside the JSON object, the response will be rejected.

Example of CORRECT response:
{"findings": [{"type": "sql_injection", "severity": "high", "confidence": 0.9, "line": 5, "message": "SQL injection vulnerability", "recommendation": "Use parameterized queries"}]}

Example of INCORRECT response (DO NOT DO THIS):
Here's the analysis:
` + "```json" + `
{"findings": [...]}
` + "```" + `

---

`
	return prefix + originalPrompt
}

// truncateForLog truncates a string for logging purposes
func truncateForLog(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "... [truncated]"
}

// ExtractJSONFromMarkdown attempts to extract JSON from markdown code blocks
// This is a fallback parser for common LLM mistakes
func ExtractJSONFromMarkdown(response string) string {
	// Look for ```json ... ``` blocks
	jsonBlockStart := "```json"
	jsonBlockEnd := "```"

	startIdx := strings.Index(response, jsonBlockStart)
	if startIdx == -1 {
		// Try without language specifier
		jsonBlockStart = "```"
		startIdx = strings.Index(response, jsonBlockStart)
	}

	if startIdx != -1 {
		// Find the content after the opening ```
		contentStart := startIdx + len(jsonBlockStart)
		endIdx := strings.Index(response[contentStart:], jsonBlockEnd)
		if endIdx != -1 {
			extracted := strings.TrimSpace(response[contentStart : contentStart+endIdx])
			log.Debug().
				Str("extracted_json", truncateForLog(extracted, 200)).
				Msg("extracted JSON from markdown code block")
			return extracted
		}
	}

	return response
}

// ParseResponseLenient is a more lenient parser that tries to extract JSON from common formats
func ParseResponseLenient(rawResponse string) (*APIResponse, error) {
	// First try normal parsing
	response, err := ParseResponse(rawResponse)
	if err == nil {
		return response, nil
	}

	// Try extracting from markdown
	extracted := ExtractJSONFromMarkdown(rawResponse)
	if extracted != rawResponse {
		response, err = ParseResponse(extracted)
		if err == nil {
			log.Debug().Msg("successfully parsed JSON after extracting from markdown")
			return response, nil
		}
	}

	// All attempts failed
	return nil, err
}
