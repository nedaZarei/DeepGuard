package reporting

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/rs/zerolog"

	"github.com/Neda-Zarei/deep-guard/internal/report"
)

// Completer answers a prompt. *llm.Client satisfies it.
type Completer interface {
	Complete(ctx context.Context, prompt string) (string, error)
}

// Findings this close (in lines) in the same file are one site.
const judgeSiteWindow = 3

// Source lines shown on each side of a site.
const judgeContext = 15

// Each template reports independently, so one vulnerable line often carries
// several types (xss, sqli and auth on the same request handler). The judge
// sees every type reported at a site and keeps at most one. Asking for the
// type name after a one-sentence description of the weakness, rather than a
// letter, was what made a 7B model reliable at this.
const judgePrompt = `You are a senior application-security reviewer adjudicating automated findings. Several scanners reported different vulnerability types at the same code location. Decide, from the code alone, which of the candidate reports describe a real, distinct vulnerability at that location. Usually one is right; sometimes none; rarely more than one. Respond ONLY with a JSON object.

Code (%s, lines %d-%d; the reported location is around line %d):
` + "```" + `
%s
` + "```" + `

Candidate types reported at this location (name: scanner's note):
%s

Rules:
- Judge from the code shown. Do not assume input is sanitised elsewhere unless the code shows it.
- A type is correct only if the code at this location actually has that class of weakness.
- Two names for the same weakness count as one: keep the more precise.
- Selecting none is a valid answer.

First describe the weakness you see in one sentence. Then give AT MOST ONE candidate TYPE NAME (exactly as written above) that most precisely names that weakness, or an empty list if none applies.

Return exactly:
{"weakness": "<one sentence>", "selected_types": ["<type name>", ...] or [], "line": <integer line number that best evidences it, or null>, "confidence": <0.0-1.0>}`

type judgeReply struct {
	SelectedTypes []string        `json:"selected_types"`
	Line          json.RawMessage `json:"line"`
}

var leadingInt = regexp.MustCompile(`\d+`)

func groupSites(findings []report.Finding) [][]report.Finding {
	byFile := map[string][]report.Finding{}
	var files []string
	for _, f := range findings {
		if _, ok := byFile[f.File]; !ok {
			files = append(files, f.File)
		}
		byFile[f.File] = append(byFile[f.File], f)
	}
	sort.Strings(files)
	var sites [][]report.Finding
	for _, file := range files {
		fs := byFile[file]
		sort.SliceStable(fs, func(i, j int) bool { return fs[i].Line < fs[j].Line })
		cur := []report.Finding{fs[0]}
		for _, f := range fs[1:] {
			if f.Line-cur[len(cur)-1].Line <= judgeSiteWindow {
				cur = append(cur, f)
				continue
			}
			sites = append(sites, cur)
			cur = []report.Finding{f}
		}
		sites = append(sites, cur)
	}
	return sites
}

func excerpt(lines []string, center int) (int, int, string) {
	lo, hi := center-judgeContext, center+judgeContext
	if lo < 1 {
		lo = 1
	}
	if hi > len(lines) {
		hi = len(lines)
	}
	var b strings.Builder
	for i := lo; i <= hi; i++ {
		fmt.Fprintf(&b, "%d: %s\n", i, lines[i-1])
	}
	return lo, hi, strings.TrimRight(b.String(), "\n")
}

func parseJudgeReply(raw string) (judgeReply, error) {
	raw = strings.TrimSpace(raw)
	if i, j := strings.Index(raw, "{"), strings.LastIndex(raw, "}"); i >= 0 && j > i {
		raw = raw[i : j+1]
	}
	var r judgeReply
	err := json.Unmarshal([]byte(raw), &r)
	return r, err
}

func judgeLine(raw json.RawMessage) (int, bool) {
	var n int
	if json.Unmarshal(raw, &n) == nil {
		return n, true
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		if m := leadingInt.FindString(s); m != "" {
			fmt.Sscanf(m, "%d", &n)
			return n, true
		}
	}
	return 0, false
}

// JudgeSites asks the model to pick one type per contested site. Sites with a
// single type pass through untouched. A failed call keeps the site's findings
// rather than dropping them, so an outage costs precision, not recall.
func JudgeSites(ctx context.Context, findings []report.Finding, model Completer, logger zerolog.Logger) ([]report.Finding, report.JudgeStats) {
	stats := report.JudgeStats{Enabled: true, TotalFindings: len(findings)}
	out := make([]report.Finding, 0, len(findings))

	for _, site := range groupSites(findings) {
		best := map[string]report.Finding{}
		for _, f := range site {
			if cur, ok := best[f.Type]; !ok || f.Confidence > cur.Confidence {
				best[f.Type] = f
			}
		}
		if len(best) < 2 {
			stats.SitesUncontested++
			out = append(out, site...)
			continue
		}
		stats.SitesContested++

		raw, err := os.ReadFile(site[0].File)
		if err != nil {
			stats.Errors++
			out = append(out, site...)
			continue
		}
		lines := strings.Split(string(raw), "\n")
		sum := 0
		for _, f := range site {
			sum += f.Line
		}
		center := (sum + len(site)/2) / len(site)
		lo, hi, code := excerpt(lines, center)

		types := make([]string, 0, len(best))
		for t := range best {
			types = append(types, t)
		}
		sort.Strings(types)
		var cands strings.Builder
		for _, t := range types {
			fmt.Fprintf(&cands, "- %s: %s\n", t, best[t].Message)
		}
		prompt := fmt.Sprintf(judgePrompt, site[0].File, lo, hi, center, code, strings.TrimRight(cands.String(), "\n"))

		reply, err := model.Complete(ctx, prompt)
		if err == nil {
			var parsed judgeReply
			parsed, err = parseJudgeReply(reply)
			if err == nil {
				stats.Calls++
				var kept []report.Finding
				for _, t := range parsed.SelectedTypes {
					f, ok := best[strings.TrimSpace(t)]
					if !ok {
						continue
					}
					if n, ok := judgeLine(parsed.Line); ok && n >= lo && n <= hi && abs(n-f.Line) <= judgeSiteWindow*2 {
						f.ReportedLine, f.Line = f.Line, n
					}
					kept = append(kept, f)
					break
				}
				if len(kept) == 0 {
					stats.SelectedNone++
				} else {
					stats.SelectedOne++
				}
				stats.Removed += len(site) - len(kept)
				out = append(out, kept...)
				continue
			}
		}
		stats.Errors++
		logger.Warn().Str("component", "judge").Str("file", site[0].File).Int("line", center).Err(err).
			Msg("judge call failed; keeping site findings")
		out = append(out, site...)
	}

	stats.KeptFindings = len(out)
	logger.Info().Str("component", "judge").
		Int("contested", stats.SitesContested).Int("calls", stats.Calls).Int("none", stats.SelectedNone).
		Int("removed", stats.Removed).Int("errors", stats.Errors).Msg("judge complete")
	return out, stats
}
