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

	// Resolve absolute line number.
	// Prompts now show line-numbered source (e.g. " 42: const q = ...") so the
	// LLM should return the absolute file line directly.  Verify the reported
	// number falls inside the chunk window; if so use it verbatim.  Otherwise
	// fall back to the old offset formula in case the LLM returned a 1-based
	// relative line (for robustness against non-compliant responses).
	if finding.Line >= chunk.StartLine && finding.Line <= chunk.EndLine {
		finding.AbsoluteLine = finding.Line
	} else {
		finding.AbsoluteLine = chunk.StartLine + (finding.Line - 1)
	}
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
