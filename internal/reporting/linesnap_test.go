package reporting

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"

	"github.com/Neda-Zarei/deep-guard/internal/report"
)

const snapSource = `import sqlite3

def get_user(conn, name):
    cur = conn.cursor()
    query = "SELECT * FROM users WHERE name = '" + name + "'"
    cur.execute(query)
    return cur.fetchone()

def unrelated():
    return 1

def get_user_again(conn, name):
    query = "SELECT * FROM users WHERE name = '" + name + "'"
    return conn.execute(query)
`

func writeSnapFixture(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "app.py")
	if err := os.WriteFile(p, []byte(snapSource), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func find(file string, line int, typ, quote string, conf float64) report.Finding {
	return report.Finding{File: file, Line: line, Type: typ, Quote: quote, Confidence: conf, Severity: "high"}
}

func TestSnap_ConfirmedWhenQuoteAtReportedLine(t *testing.T) {
	p := writeSnapFixture(t)
	out, st := SnapLinesToQuotes([]report.Finding{
		find(p, 5, "sql_injection", `query = "SELECT * FROM users WHERE name = '" + name + "'"`, 0.9),
	}, 40, false, zerolog.Nop())
	if st.Confirmed != 1 || st.Snapped != 0 || out[0].Line != 5 || out[0].ReportedLine != 0 {
		t.Fatalf("expected confirmed at line 5, got stats=%+v line=%d reported=%d", st, out[0].Line, out[0].ReportedLine)
	}
}

func TestSnap_MovesToNearestQuoteMatch(t *testing.T) {
	p := writeSnapFixture(t)
	// Model anchored on the function entry (line 3); quote is line 5. Line 13 also
	// matches but is farther, so the nearer one wins.
	out, st := SnapLinesToQuotes([]report.Finding{
		find(p, 3, "sql_injection", `query = "SELECT * FROM users WHERE name = '" + name + "'"`, 0.9),
	}, 40, false, zerolog.Nop())
	if st.Snapped != 1 || out[0].Line != 5 || out[0].ReportedLine != 3 {
		t.Fatalf("expected snap 3->5, got stats=%+v line=%d reported=%d", st, out[0].Line, out[0].ReportedLine)
	}
}

func TestSnap_StripsLineNumberPrefixAndWhitespace(t *testing.T) {
	p := writeSnapFixture(t)
	out, st := SnapLinesToQuotes([]report.Finding{
		find(p, 4, "sql_injection", `  5:   query = "SELECT * FROM users WHERE name = '"   +  name + "'"`, 0.9),
	}, 40, false, zerolog.Nop())
	if st.Snapped != 1 || out[0].Line != 5 {
		t.Fatalf("expected prefix-stripped quote to snap to 5, got stats=%+v line=%d", st, out[0].Line)
	}
}

func TestSnap_TooFarIsLeftAlone(t *testing.T) {
	p := writeSnapFixture(t)
	out, st := SnapLinesToQuotes([]report.Finding{
		find(p, 3, "sql_injection", `return conn.execute(query)`, 0.9), // only at line 14, distance 11
	}, 5, false, zerolog.Nop())
	if st.TooFar != 1 || out[0].Line != 3 || out[0].ReportedLine != 0 {
		t.Fatalf("expected too-far finding untouched, got stats=%+v line=%d", st, out[0].Line)
	}
}

func TestSnap_QuoteNotFound_KeepOrDropByPolicy(t *testing.T) {
	p := writeSnapFixture(t)
	f := find(p, 5, "sql_injection", `this text is nowhere in the file at all`, 0.9)

	kept, st := SnapLinesToQuotes([]report.Finding{f}, 40, false, zerolog.Nop())
	if st.QuoteNotFound != 1 || st.Dropped != 0 || len(kept) != 1 {
		t.Fatalf("keep policy: expected 1 kept, stats=%+v", st)
	}
	dropped, st2 := SnapLinesToQuotes([]report.Finding{f}, 40, true, zerolog.Nop())
	if st2.QuoteNotFound != 1 || st2.Dropped != 1 || len(dropped) != 0 {
		t.Fatalf("drop policy: expected 0 kept, stats=%+v", st2)
	}
}

func TestSnap_NoQuoteIsPassedThrough(t *testing.T) {
	p := writeSnapFixture(t)
	out, st := SnapLinesToQuotes([]report.Finding{find(p, 3, "sql_injection", "", 0.9)}, 40, true, zerolog.Nop())
	if st.WithoutQuote != 1 || len(out) != 1 || out[0].Line != 3 {
		t.Fatalf("expected quote-less finding untouched, stats=%+v", st)
	}
}

func TestSnap_CollapsesDuplicatesAfterSnapKeepingMaxConfidence(t *testing.T) {
	p := writeSnapFixture(t)
	q := `query = "SELECT * FROM users WHERE name = '" + name + "'"`
	out, st := SnapLinesToQuotes([]report.Finding{
		find(p, 3, "sql_injection", q, 0.7), // entry-line report, snaps to 5
		find(p, 5, "sql_injection", q, 0.95),
		find(p, 5, "xss", q, 0.6), // different type: must survive (that's the judge's job)
	}, 40, false, zerolog.Nop())
	if st.DuplicatesRemoved != 1 || len(out) != 2 {
		t.Fatalf("expected one duplicate removed, 2 left; stats=%+v n=%d", st, len(out))
	}
	for _, f := range out {
		if f.Type == "sql_injection" && f.Confidence != 0.95 {
			t.Fatalf("expected max-confidence duplicate kept, got %.2f", f.Confidence)
		}
	}
}

func TestSnap_UnreadableFileIsCountedNotFatal(t *testing.T) {
	out, st := SnapLinesToQuotes([]report.Finding{
		find("/nonexistent/x.py", 3, "sql_injection", "anything", 0.9),
	}, 40, true, zerolog.Nop())
	if st.FileUnreadable != 1 || len(out) != 1 {
		t.Fatalf("expected unreadable file to be counted and finding kept, stats=%+v", st)
	}
}
