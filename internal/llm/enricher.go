package llm

import (
	"github.com/Neda-Zarei/deep-guard/internal/chunker"
	"github.com/Neda-Zarei/deep-guard/pkg/types"
)

// EnrichFinding adds context information from the code chunk to a finding
func EnrichFinding(finding *types.Finding, chunk *chunker.CodeChunk) {
	// Set chunk context
	finding.ChunkID = chunk.ID
	finding.FilePath = chunk.FilePath
	finding.FunctionName = chunk.FunctionName

	// Set line range context
	finding.LineRangeStart = chunk.StartLine
	finding.LineRangeEnd = chunk.EndLine

	// Calculate absolute line number
	// Finding.Line is relative to the chunk (1-indexed within the chunk)
	// chunk.StartLine is the absolute line number where the chunk starts (1-indexed)
	// AbsoluteLine = StartLine + (Line - 1)
	finding.AbsoluteLine = chunk.StartLine + (finding.Line - 1)
}

// EnrichFindings adds context information to all findings in a response
func EnrichFindings(response *APIResponse, chunk *chunker.CodeChunk) {
	if response == nil || response.Findings == nil {
		return
	}

	for i := range response.Findings {
		EnrichFinding(&response.Findings[i], chunk)
	}
}
