package llm

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/Neda-Zarei/deep-guard/internal/chunker"
	"github.com/Neda-Zarei/deep-guard/internal/kb"
	"github.com/rs/zerolog/log"
	"github.com/sashabaranov/go-openai"
)

const (
	// gapgpt api base url (compatible with openai api)
	GapGPTBaseURL = "https://api.gapgpt.app/v1"

	// alternative cdn url for gapgpt
	GapGPTCDNURL = "https://api.gapapi.com/v1"
)

// client wraps the openai api client with retry logic and token tracking
type Client struct {
	client  *openai.Client
	model   string
	tracker *Tracker
}

// newClient creates a new llm client configured for gapgpt service
func NewClient(apiKey, model string) *Client {
	config := openai.DefaultConfig(apiKey)
	config.BaseURL = GapGPTBaseURL

	return &Client{
		client:  openai.NewClientWithConfig(config),
		model:   model,
		tracker: NewTracker(),
	}
}

// newClientWithBaseURL creates a new llm client with custom base url (for testing)
func NewClientWithBaseURL(apiKey, model, baseURL string) *Client {
	config := openai.DefaultConfig(apiKey)
	config.BaseURL = baseURL

	return &Client{
		client:  openai.NewClientWithConfig(config),
		model:   model,
		tracker: NewTracker(),
	}
}

// analyze sends a code chunk with kb context to the llm for vulnerability analysis
// returns structured response with findings, token usage, and cost
func (c *Client) Analyze(ctx context.Context, chunk chunker.CodeChunk, kbContext []kb.KBEntry, prompt string) (*Response, error) {
	log.Debug().
		Str("component", "llm").
		Str("chunk_id", chunk.ID).
		Str("function", chunk.FunctionName).
		Str("model", c.model).
		Msg("starting llm analysis")

	var response *Response
	var analyzeErr error

	// wrap the api call with retry logic
	err := withRetry(ctx, func(attemptCtx context.Context) error {
		resp, err := c.callAPI(attemptCtx, prompt)
		if err != nil {
			return err
		}
		response = resp
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("llm analysis failed: %w", err)
	}

	// record token usage
	c.tracker.Record(response.PromptTokens, response.CompletionTokens, response.Cost)

	log.Info().
		Str("component", "llm").
		Str("chunk_id", chunk.ID).
		Int("prompt_tokens", response.PromptTokens).
		Int("completion_tokens", response.CompletionTokens).
		Float64("cost", response.Cost).
		Msg("llm analysis completed")

	return response, analyzeErr
}

// callAPI makes a single api call to openai/gapgpt
func (c *Client) callAPI(ctx context.Context, prompt string) (*Response, error) {
	// create chat completion request
	req := openai.ChatCompletionRequest{
		Model: c.model,
		Messages: []openai.ChatCompletionMessage{
			{
				Role:    openai.ChatMessageRoleUser,
				Content: prompt,
			},
		},
		Temperature: 0.0, // deterministic output for security analysis
	}

	// call api
	resp, err := c.client.CreateChatCompletion(ctx, req)
	if err != nil {
		return nil, c.handleAPIError(err)
	}

	// validate response
	if len(resp.Choices) == 0 {
		return nil, errors.New("no choices in api response")
	}

	// extract token usage
	promptTokens := resp.Usage.PromptTokens
	completionTokens := resp.Usage.CompletionTokens

	// calculate cost
	cost := calculateCost(c.model, promptTokens, completionTokens)

	// build response
	response := &Response{
		Findings:         resp.Choices[0].Message.Content,
		PromptTokens:     promptTokens,
		CompletionTokens: completionTokens,
		Cost:             cost,
		ModelUsed:        c.model,
	}

	return response, nil
}

// handleAPIError converts openai api errors to retryable errors when appropriate
func (c *Client) handleAPIError(err error) error {
	// check if it's an openai api error
	var apiErr *openai.APIError
	if errors.As(err, &apiErr) {
		statusCode := apiErr.HTTPStatusCode

		// client errors (4xx except 429) are not retryable
		if statusCode >= 400 && statusCode < 500 && statusCode != http.StatusTooManyRequests {
			log.Error().
				Str("component", "llm").
				Int("status_code", statusCode).
				Str("message", apiErr.Message).
				Msg("client error, not retrying")
			return fmt.Errorf("api client error (status %d): %s", statusCode, apiErr.Message)
		}

		// rate limit or server error - retryable
		if isRetryable(statusCode) {
			return &retryableError{
				statusCode: statusCode,
				message:    apiErr.Message,
				retryAfter: 0, // retry-after header not easily accessible from apierror
			}
		}
	}

	// network or other errors - wrap as retryable
	log.Debug().
		Str("component", "llm").
		Err(err).
		Msg("network or unknown error, treating as retryable")

	return &retryableError{
		statusCode: 0,
		message:    err.Error(),
		retryAfter: 0,
	}
}

// getTracker returns the token/cost tracker
func (c *Client) GetTracker() *Tracker {
	return c.tracker
}

// exceedsBudget checks if the cumulative cost exceeds the budget cap
func (c *Client) ExceedsBudget(budgetCap float64) bool {
	return c.tracker.ExceedsBudget(budgetCap)
}
