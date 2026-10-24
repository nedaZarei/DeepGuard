package reporting

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/rs/zerolog"

	"github.com/Neda-Zarei/deep-guard/internal/report"
)

// The verifier sees one finding at a time with fresh context. Measured on
// RealVuln it removed only false positives for a 7B model (13 of 13), so the
// default on a failed call is to keep the finding.
const verifyPrompt = `You are a senior application-security reviewer. A scanner reported one vulnerability at one code location. Decide from the code alone whether that report is correct. Respond ONLY with a JSON object.

Code (%s, lines %d-%d):
` + "```" + `
%s
` + "```" + `

Reported finding: %s at line %d. Scanner's note: %s

Is this a real %s vulnerability at this location? Do not assume sanitisation that the code does not show.
Return exactly: {"applies": true or false, "confidence": <0.0-1.0>, "reason": "<one sentence>"}`

type verifyReply struct {
	Applies bool `json:"applies"`
}

// VerifyFindings re-checks every finding in isolation and drops those the
// model rejects. A failed call keeps the finding.
func VerifyFindings(ctx context.Context, findings []report.Finding, model Completer, logger zerolog.Logger) ([]report.Finding, report.VerifyStats) {
	stats := report.VerifyStats{Enabled: true, TotalFindings: len(findings)}
	files := map[string][]string{}
	out := make([]report.Finding, 0, len(findings))

	for _, f := range findings {
		lines, ok := files[f.File]
		if !ok {
			raw, err := os.ReadFile(f.File)
			if err != nil {
				stats.Errors++
				out = append(out, f)
				continue
			}
			lines = strings.Split(string(raw), "\n")
			files[f.File] = lines
		}
		lo, hi, code := excerpt(lines, f.Line)
		prompt := fmt.Sprintf(verifyPrompt, f.File, lo, hi, code, f.Type, f.Line, f.Message, f.Type)

		reply, err := model.Complete(ctx, prompt)
		if err == nil {
			reply = strings.TrimSpace(reply)
			if i, j := strings.Index(reply, "{"), strings.LastIndex(reply, "}"); i >= 0 && j > i {
				reply = reply[i : j+1]
			}
			var parsed verifyReply
			if err = json.Unmarshal([]byte(reply), &parsed); err == nil {
				stats.Calls++
				if parsed.Applies {
					stats.Confirmed++
					out = append(out, f)
				} else {
					stats.Rejected++
				}
				continue
			}
		}
		stats.Errors++
		logger.Warn().Str("component", "verify").Str("file", f.File).Int("line", f.Line).Err(err).
			Msg("verify call failed; keeping finding")
		out = append(out, f)
	}

	stats.KeptFindings = len(out)
	logger.Info().Str("component", "verify").
		Int("calls", stats.Calls).Int("confirmed", stats.Confirmed).Int("rejected", stats.Rejected).
		Int("errors", stats.Errors).Msg("verify complete")
	return out, stats
}
