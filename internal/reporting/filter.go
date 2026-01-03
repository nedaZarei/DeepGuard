package reporting

import (
	"github.com/Neda-Zarei/deep-guard/internal/report"
	"github.com/rs/zerolog"
)

// FilterFindingsByConfidence filters findings based on confidence threshold.
// Returns findings that meet or exceed the threshold, along with filtering statistics.
func FilterFindingsByConfidence(findings []report.Finding, threshold float64, logger zerolog.Logger) ([]report.Finding, report.FilteringStats) {
	stats := report.FilteringStats{
		Enabled:       threshold > 0.0,
		TotalFindings: len(findings),
		ThresholdUsed: threshold,
	}

	// Special case: threshold of 0.0 means include all findings
	if threshold == 0.0 {
		stats.KeptFindings = len(findings)
		stats.FilteredFindings = 0
		logger.Info().
			Str("component", "filter").
			Int("total_findings", stats.TotalFindings).
			Float64("threshold", threshold).
			Msg("No filtering applied (threshold 0.0)")
		return findings, stats
	}

	// Filter findings
	var filtered []report.Finding
	for _, finding := range findings {
		if finding.Confidence >= threshold {
			filtered = append(filtered, finding)
		} else {
			// Log filtered finding at debug level
			logger.Debug().
				Str("component", "filter").
				Str("finding_id", finding.ID).
				Str("type", finding.Type).
				Str("file", finding.File).
				Int("line", finding.Line).
				Float64("confidence", finding.Confidence).
				Float64("threshold", threshold).
				Msg("Filtered finding below confidence threshold")
		}
	}

	stats.KeptFindings = len(filtered)
	stats.FilteredFindings = stats.TotalFindings - stats.KeptFindings

	// Log summary at info level
	if stats.FilteredFindings > 0 {
		logger.Info().
			Str("component", "filter").
			Int("filtered", stats.FilteredFindings).
			Int("total", stats.TotalFindings).
			Float64("threshold", threshold).
			Msgf("Filtered %d of %d findings below confidence threshold %.2f",
				stats.FilteredFindings, stats.TotalFindings, threshold)
	} else {
		logger.Info().
			Str("component", "filter").
			Int("total", stats.TotalFindings).
			Float64("threshold", threshold).
			Msg("All findings meet confidence threshold")
	}

	return filtered, stats
}
