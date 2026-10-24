package reporting

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rs/zerolog"

	"github.com/Neda-Zarei/deep-guard/internal/report"
)

type fakeModel struct {
	reply   string
	err     error
	prompts []string
}

func (m *fakeModel) Complete(_ context.Context, prompt string) (string, error) {
	m.prompts = append(m.prompts, prompt)
	return m.reply, m.err
}

func judgeFixture(t *testing.T) string {
	t.Helper()
	var b strings.Builder
	for i := 1; i <= 40; i++ {
		b.WriteString("line\n")
	}
	p := filepath.Join(t.TempDir(), "app.py")
	if err := os.WriteFile(p, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestJudge_UncontestedSitePassesThroughWithoutCall(t *testing.T) {
	p := judgeFixture(t)
	m := &fakeModel{}
	out, st := JudgeSites(context.Background(), []report.Finding{
		{File: p, Line: 10, Type: "sql_injection", Confidence: 0.9},
		{File: p, Line: 30, Type: "xss", Confidence: 0.9},
	}, m, zerolog.New(io.Discard))
	if len(m.prompts) != 0 || len(out) != 2 || st.SitesUncontested != 2 || st.SitesContested != 0 {
		t.Fatalf("prompts=%d out=%d stats=%+v", len(m.prompts), len(out), st)
	}
}

func TestJudge_KeepsOnlySelectedTypeAndSnapsLine(t *testing.T) {
	p := judgeFixture(t)
	m := &fakeModel{reply: `{"weakness": "user input in query", "selected_types": ["sql_injection"], "line": 12, "confidence": 0.9}`}
	out, st := JudgeSites(context.Background(), []report.Finding{
		{File: p, Line: 10, Type: "sql_injection", Confidence: 0.8, Message: "concat"},
		{File: p, Line: 10, Type: "xss", Confidence: 0.9, Message: "reflect"},
		{File: p, Line: 11, Type: "auth_issue", Confidence: 0.7, Message: "no check"},
	}, m, zerolog.New(io.Discard))
	if len(out) != 1 || out[0].Type != "sql_injection" || out[0].Line != 12 || out[0].ReportedLine != 10 {
		t.Fatalf("out=%+v", out)
	}
	if st.Calls != 1 || st.SelectedOne != 1 || st.Removed != 2 {
		t.Fatalf("stats=%+v", st)
	}
	if !strings.Contains(m.prompts[0], "- xss: reflect") || !strings.Contains(m.prompts[0], "10: line") {
		t.Fatalf("prompt missing candidates or code:\n%s", m.prompts[0])
	}
}

func TestJudge_HighestConfidencePerTypeIsTheCandidate(t *testing.T) {
	p := judgeFixture(t)
	m := &fakeModel{reply: `{"selected_types": ["xss"], "line": null}`}
	out, _ := JudgeSites(context.Background(), []report.Finding{
		{File: p, Line: 10, Type: "xss", Confidence: 0.6, Message: "weak"},
		{File: p, Line: 11, Type: "xss", Confidence: 0.95, Message: "strong"},
		{File: p, Line: 10, Type: "sql_injection", Confidence: 0.9},
	}, m, zerolog.New(io.Discard))
	if len(out) != 1 || out[0].Message != "strong" || out[0].Line != 11 {
		t.Fatalf("out=%+v", out)
	}
}

func TestJudge_SelectingNoneRemovesSite(t *testing.T) {
	p := judgeFixture(t)
	m := &fakeModel{reply: `{"selected_types": [], "line": null}`}
	out, st := JudgeSites(context.Background(), []report.Finding{
		{File: p, Line: 10, Type: "xss", Confidence: 0.9},
		{File: p, Line: 10, Type: "ssrf", Confidence: 0.9},
	}, m, zerolog.New(io.Discard))
	if len(out) != 0 || st.SelectedNone != 1 || st.Removed != 2 {
		t.Fatalf("out=%d stats=%+v", len(out), st)
	}
}

func TestJudge_UnknownTypeNameAndSecondSelectionAreIgnored(t *testing.T) {
	p := judgeFixture(t)
	m := &fakeModel{reply: `{"selected_types": ["code_injection", "xss", "ssrf"], "line": "12: code"}`}
	out, _ := JudgeSites(context.Background(), []report.Finding{
		{File: p, Line: 10, Type: "xss", Confidence: 0.9},
		{File: p, Line: 10, Type: "ssrf", Confidence: 0.9},
	}, m, zerolog.New(io.Discard))
	if len(out) != 1 || out[0].Type != "xss" || out[0].Line != 12 {
		t.Fatalf("out=%+v", out)
	}
}

func TestJudge_FailedCallKeepsSite(t *testing.T) {
	p := judgeFixture(t)
	for _, m := range []*fakeModel{{err: errors.New("boom")}, {reply: "not json"}} {
		out, st := JudgeSites(context.Background(), []report.Finding{
			{File: p, Line: 10, Type: "xss", Confidence: 0.9},
			{File: p, Line: 10, Type: "ssrf", Confidence: 0.9},
		}, m, zerolog.New(io.Discard))
		if len(out) != 2 || st.Errors != 1 || st.Calls != 0 {
			t.Fatalf("out=%d stats=%+v", len(out), st)
		}
	}
}

func TestJudge_LineSnapRejectedWhenFarFromSite(t *testing.T) {
	p := judgeFixture(t)
	m := &fakeModel{reply: `{"selected_types": ["xss"], "line": 25}`}
	out, _ := JudgeSites(context.Background(), []report.Finding{
		{File: p, Line: 10, Type: "xss", Confidence: 0.9},
		{File: p, Line: 10, Type: "ssrf", Confidence: 0.9},
	}, m, zerolog.New(io.Discard))
	if out[0].Line != 10 || out[0].ReportedLine != 0 {
		t.Fatalf("line should stay 10, got %+v", out[0])
	}
}

func TestJudge_UnreadableFileKeepsSite(t *testing.T) {
	m := &fakeModel{}
	out, st := JudgeSites(context.Background(), []report.Finding{
		{File: "/nonexistent/x.py", Line: 10, Type: "xss"},
		{File: "/nonexistent/x.py", Line: 10, Type: "ssrf"},
	}, m, zerolog.New(io.Discard))
	if len(out) != 2 || st.Errors != 1 || len(m.prompts) != 0 {
		t.Fatalf("out=%d stats=%+v prompts=%d", len(out), st, len(m.prompts))
	}
}
