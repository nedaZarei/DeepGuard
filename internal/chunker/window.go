package chunker

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// WindowChunks splits a file into fixed-size line windows, ignoring syntax. It is
// the control for the AST chunking ablation: same prompt sizes, no function boundaries.
func WindowChunks(content []byte, filePath, language string, frameworks []string, size int) []CodeChunk {
	lines := strings.Split(string(content), "\n")
	var chunks []CodeChunk
	for start := 0; start < len(lines); start += size {
		end := start + size
		if end > len(lines) {
			end = len(lines)
		}
		src := strings.Join(lines[start:end], "\n")
		if strings.TrimSpace(src) == "" {
			continue
		}
		hash := sha256.Sum256([]byte(fmt.Sprintf("%s:%d:%s", filePath, start+1, src)))
		chunks = append(chunks, CodeChunk{
			ID:            hex.EncodeToString(hash[:]),
			FilePath:      filePath,
			StartLine:     start + 1,
			EndLine:       end,
			FunctionName:  fmt.Sprintf("lines_%d_%d", start+1, end),
			Language:      language,
			Source:        src,
			Tokens:        estimateTokens(src),
			Frameworks:    frameworks,
			NormalizedSrc: src,
		})
	}
	return chunks
}
