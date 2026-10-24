package chunker

import (
	"strings"
	"testing"
)

func TestWindowChunks_CoversFileInFixedWindows(t *testing.T) {
	var b strings.Builder
	for i := 1; i <= 130; i++ {
		b.WriteString("x = 1\n")
	}
	chunks := WindowChunks([]byte(b.String()), "/a.py", "python", nil, 60)
	if len(chunks) != 3 {
		t.Fatalf("got %d chunks", len(chunks))
	}
	if chunks[0].StartLine != 1 || chunks[0].EndLine != 60 || chunks[2].StartLine != 121 || chunks[2].EndLine != 131 {
		t.Fatalf("ranges: %+v", []int{chunks[0].StartLine, chunks[0].EndLine, chunks[2].StartLine, chunks[2].EndLine})
	}
}

func TestWindowChunks_SkipsBlankWindows(t *testing.T) {
	src := "x = 1\n" + strings.Repeat("\n", 70)
	if n := len(WindowChunks([]byte(src), "/a.py", "python", nil, 60)); n != 1 {
		t.Fatalf("got %d chunks", n)
	}
}
