package reporting

import (
	"os"
	"regexp"
	"strings"

	"github.com/rs/zerolog"

	"github.com/Neda-Zarei/deep-guard/internal/report"
)

// Line attribution is the largest single source of "right finding, wrong
// location" errors: models tend to anchor on a function's entry line or on
// the execution line rather than the construction line. Rather than trusting
// the reported line number, each template now asks for the offending source
// line verbatim, and this stage anchors the finding to where that text really
// is. It is deterministic and costs no model calls.

// DefaultSnapMaxDistance bounds how far (in lines) a finding may be moved to
// reach its quote. Beyond that the quote is more likely a different, similar
// line than a mis-numbered one, so the finding is left where it was reported.
const DefaultSnapMaxDistance = 40

// minFragmentLen guards substring matching: quotes shorter than this are too
// generic (e.g. "}" or "return x") to locate reliably.
const minFragmentLen = 12

// A model sometimes copies the listing's line-number prefix into the quote.
var lineNumberPrefix = regexp.MustCompile(`^\s*\d+\s*[:|]\s?`)
var multiSpace = regexp.MustCompile(`\s+`)

// normalizeLine makes a source line and a model quote comparable: strips a
// leading line-number prefix, trims, and collapses internal whitespace.
func normalizeLine(s string) string {
	s = lineNumberPrefix.ReplaceAllString(s, "")
	s = strings.TrimSpace(s)
	return multiSpace.ReplaceAllString(s, " ")
}

// fileCache reads each file once per SnapLinesToQuotes call.
type fileCache struct {
	lines map[string][]string
	bad   map[string]bool
}

func (c *fileCache) get(path string) ([]string, bool) {
	if l, ok := c.lines[path]; ok {
		return l, true
	}
	if c.bad[path] {
		return nil, false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		c.bad[path] = true
		return nil, false
	}
	raw := strings.Split(string(data), "\n")
	norm := make([]string, len(raw))
	for i, l := range raw {
		norm[i] = normalizeLine(l)
	}
	c.lines[path] = norm
	return norm, true
}

// locate returns the 1-based line numbers whose normalized text equals the
// quote, falling back to substring containment for longer quotes.
func locate(lines []string, quote string) []int {
	q := normalizeLine(quote)
	if q == "" {
		return nil
	}
	var exact []int
	for i, l := range lines {
		if l == q {
			exact = append(exact, i+1)
		}
	}
	if len(exact) > 0 || len(q) < minFragmentLen {
		return exact
	}
	var contains []int
	for i, l := range lines {
		if strings.Contains(l, q) || strings.Contains(q, l) && len(l) >= minFragmentLen {
			contains = append(contains, i+1)
		}
	}
	return contains
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// SnapLinesToQuotes anchors each finding's Line to the location of its Quote,
// then collapses findings that ended up on the same (file, line, type).
//
// Policy for a quote that cannot be found in the file: when dropUnverifiable
// is false (default) the finding is kept unchanged and only counted, so
// recall is never traded away silently; when true it is removed, which is the
// stricter behaviour the prompt announces to the model. Both are measured so
// the paper can report the trade-off.
func SnapLinesToQuotes(findings []report.Finding, maxDistance int, dropUnverifiable bool, logger zerolog.Logger) ([]report.Finding, report.LineSnapStats) {
	stats := report.LineSnapStats{Enabled: true, MaxDistance: maxDistance, TotalFindings: len(findings)}
	if maxDistance <= 0 {
		maxDistance = DefaultSnapMaxDistance
		stats.MaxDistance = maxDistance
	}
	cache := &fileCache{lines: map[string][]string{}, bad: map[string]bool{}}

	out := make([]report.Finding, 0, len(findings))
	for _, f := range findings {
		if strings.TrimSpace(f.Quote) == "" {
			stats.WithoutQuote++
			out = append(out, f)
			continue
		}
		stats.WithQuote++

		lines, ok := cache.get(f.File)
		if !ok {
			stats.FileUnreadable++
			out = append(out, f)
			continue
		}
		cands := locate(lines, f.Quote)
		if len(cands) == 0 {
			stats.QuoteNotFound++
			if dropUnverifiable {
				stats.Dropped++
				logger.Debug().Str("file", f.File).Int("line", f.Line).Str("type", f.Type).
					Msg("dropping finding: quote not found in file")
				continue
			}
			out = append(out, f)
			continue
		}

		confirmed := false
		best, bestDist := 0, -1
		for _, c := range cands {
			if c == f.Line {
				confirmed = true
				break
			}
			if d := abs(c - f.Line); bestDist < 0 || d < bestDist {
				best, bestDist = c, d
			}
		}
		switch {
		case confirmed:
			stats.Confirmed++
		case bestDist <= maxDistance:
			stats.Snapped++
			logger.Debug().Str("file", f.File).Int("from", f.Line).Int("to", best).Str("type", f.Type).
				Msg("snapped finding line to quoted source")
			f.ReportedLine = f.Line
			f.Line = best
		default:
			stats.TooFar++
		}
		out = append(out, f)
	}

	// Same finding reported twice (typically once at the function entry and
	// once at the real line) now lands on one line: keep the higher confidence.
	type key struct {
		file, typ string
		line      int
	}
	seen := make(map[key]int, len(out))
	deduped := make([]report.Finding, 0, len(out))
	for _, f := range out {
		k := key{f.File, f.Type, f.Line}
		if idx, dup := seen[k]; dup {
			stats.DuplicatesRemoved++
			if f.Confidence > deduped[idx].Confidence {
				deduped[idx] = f
			}
			continue
		}
		seen[k] = len(deduped)
		deduped = append(deduped, f)
	}
	stats.KeptFindings = len(deduped)

	logger.Info().
		Int("with_quote", stats.WithQuote).Int("confirmed", stats.Confirmed).Int("snapped", stats.Snapped).
		Int("too_far", stats.TooFar).Int("quote_not_found", stats.QuoteNotFound).Int("dropped", stats.Dropped).
		Int("duplicates_removed", stats.DuplicatesRemoved).
		Msg("line snapping complete")
	return deduped, stats
}
