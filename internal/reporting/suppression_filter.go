package reporting

import (
	"github.com/Neda-Zarei/deep-guard/internal/chunker"
	"github.com/Neda-Zarei/deep-guard/internal/report"
	"github.com/Neda-Zarei/deep-guard/internal/suppression"
	"github.com/rs/zerolog"
)

// SuppressionFilterStats tracks statistics about suppressed findings
type SuppressionFilterStats struct {
	TotalFindings      int `json:"total_findings"`
	SuppressedFindings int `json:"suppressed_findings"`
	KeptFindings       int `json:"kept_findings"`
}

// FilterSuppressedFindings filters out findings that have suppression comments
// Returns findings that should be reported along with suppression statistics
func FilterSuppressedFindings(findings []report.Finding, chunks map[string]chunker.CodeChunk, logger zerolog.Logger) ([]report.Finding, SuppressionFilterStats) {
	stats := SuppressionFilterStats{
		TotalFindings: len(findings),
	}

	var kept []report.Finding

	for _, finding := range findings {
		// Find the chunk this finding belongs to
		chunk, exists := chunks[finding.FunctionName]
		if !exists {
			// If chunk not found, keep the finding (no suppression data available)
			kept = append(kept, finding)
			continue
		}

		// Check if finding is suppressed
		suppressed, info := suppression.IsSuppressed(finding.Line, finding.Type, chunk.SuppressedLines)

		if suppressed {
			stats.SuppressedFindings++

			// Log suppressed finding at debug level
			logEvent := logger.Debug().
				Str("component", "suppression_filter").
				Str("finding_id", finding.ID).
				Str("type", finding.Type).
				Str("file", finding.File).
				Int("line", finding.Line).
				Str("suppression_type", info.Type)

			if info.Justification != "" {
				logEvent.Str("justification", info.Justification)
			}

			logEvent.Msg("Finding suppressed by inline comment")
		} else {
			kept = append(kept, finding)
		}
	}

	stats.KeptFindings = len(kept)

	// Log summary
	if stats.SuppressedFindings > 0 {
		logger.Info().
			Str("component", "suppression_filter").
			Int("suppressed", stats.SuppressedFindings).
			Int("total", stats.TotalFindings).
			Msgf("Suppressed %d of %d findings via inline comments",
				stats.SuppressedFindings, stats.TotalFindings)
	} else {
		logger.Debug().
			Str("component", "suppression_filter").
			Int("total", stats.TotalFindings).
			Msg("No findings suppressed")
	}

	return kept, stats
}
