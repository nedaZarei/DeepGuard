package reporting

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/rs/zerolog"

	"github.com/Neda-Zarei/deep-guard/internal/report"
)

type perCallModel struct {
	replies []string
	prompts []string
}

func (m *perCallModel) Complete(_ context.Context, prompt string) (string, error) {
	m.prompts = append(m.prompts, prompt)
	r := m.replies[len(m.prompts)-1]
	if r == "ERR" {
		return "", errors.New("boom")
	}
	return r, nil
}

func TestVerify_DropsRejectedKeepsConfirmed(t *testing.T) {
	p := judgeFixture(t)
	m := &perCallModel{replies: []string{
		`{"applies": true, "confidence": 0.9, "reason": "yes"}`,
		`{"applies": false, "confidence": 0.8, "reason": "no"}`,
	}}
	out, st := VerifyFindings(context.Background(), []report.Finding{
		{File: p, Line: 10, Type: "sql_injection", Message: "concat"},
		{File: p, Line: 20, Type: "xss", Message: "reflect"},
	}, m, zerolog.New(io.Discard))
	if len(out) != 1 || out[0].Type != "sql_injection" {
		t.Fatalf("out=%+v", out)
	}
	if st.Calls != 2 || st.Confirmed != 1 || st.Rejected != 1 || st.KeptFindings != 1 {
		t.Fatalf("stats=%+v", st)
	}
	if !strings.Contains(m.prompts[1], "Reported finding: xss at line 20. Scanner's note: reflect") {
		t.Fatalf("prompt:\n%s", m.prompts[1])
	}
}

func TestVerify_FailedOrUnparseableCallKeepsFinding(t *testing.T) {
	p := judgeFixture(t)
	m := &perCallModel{replies: []string{"ERR", "not json"}}
	out, st := VerifyFindings(context.Background(), []report.Finding{
		{File: p, Line: 10, Type: "xss"},
		{File: p, Line: 20, Type: "ssrf"},
	}, m, zerolog.New(io.Discard))
	if len(out) != 2 || st.Errors != 2 || st.Calls != 0 {
		t.Fatalf("out=%d stats=%+v", len(out), st)
	}
}

func TestVerify_FencedJSONIsAccepted(t *testing.T) {
	p := judgeFixture(t)
	m := &perCallModel{replies: []string{"```json\n{\"applies\": false}\n```"}}
	out, st := VerifyFindings(context.Background(), []report.Finding{{File: p, Line: 10, Type: "xss"}}, m, zerolog.New(io.Discard))
	if len(out) != 0 || st.Rejected != 1 {
		t.Fatalf("out=%d stats=%+v", len(out), st)
	}
}

func TestVerify_UnreadableFileKeepsFinding(t *testing.T) {
	m := &perCallModel{}
	out, st := VerifyFindings(context.Background(), []report.Finding{{File: "/nonexistent/x.py", Line: 3, Type: "xss"}}, m, zerolog.New(io.Discard))
	if len(out) != 1 || st.Errors != 1 || len(m.prompts) != 0 {
		t.Fatalf("out=%d stats=%+v prompts=%d", len(out), st, len(m.prompts))
	}
}
