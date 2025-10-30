package llm

// response contains the structured output from an llm analysis request
type Response struct {
	// findings contains the raw text response from the llm
	Findings string

	// promptTokens is the number of tokens in the input prompt
	PromptTokens int

	// completionTokens is the number of tokens in the llm's response
	CompletionTokens int

	// cost is the total cost in usd for this api call
	Cost float64

	// modelUsed is the model name that was used (e.g., "gpt-4o", "gpt-4o-mini")
	ModelUsed string
}

// model pricing constants (per 1M tokens) as of 2024
// source: https://openai.com/api/pricing/
const (
	// gpt-4o pricing
	GPT4oInputPricePer1M  = 2.50  // $2.50 per 1M input tokens
	GPT4oOutputPricePer1M = 10.00 // $10.00 per 1M output tokens

	// gpt-4o-mini pricing
	GPT4oMiniInputPricePer1M  = 0.150 // $0.15 per 1M input tokens
	GPT4oMiniOutputPricePer1M = 0.600 // $0.60 per 1M output tokens
)

// calculateCost computes the cost in usd for a given token usage
func calculateCost(model string, promptTokens, completionTokens int) float64 {
	var inputPrice, outputPrice float64

	switch model {
	case "gpt-4o":
		inputPrice = GPT4oInputPricePer1M
		outputPrice = GPT4oOutputPricePer1M
	case "gpt-4o-mini":
		inputPrice = GPT4oMiniInputPricePer1M
		outputPrice = GPT4oMiniOutputPricePer1M
	default:
		// default to gpt-4o-mini pricing for unknown models
		inputPrice = GPT4oMiniInputPricePer1M
		outputPrice = GPT4oMiniOutputPricePer1M
	}

	// convert tokens to millions and calculate cost
	inputCost := (float64(promptTokens) / 1_000_000.0) * inputPrice
	outputCost := (float64(completionTokens) / 1_000_000.0) * outputPrice

	return inputCost + outputCost
}
