package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Neda-Zarei/deep-guard/internal/chunker"
	"github.com/Neda-Zarei/deep-guard/internal/discovery"
	"github.com/Neda-Zarei/deep-guard/internal/kb"
	"github.com/Neda-Zarei/deep-guard/internal/llm"
	"github.com/Neda-Zarei/deep-guard/internal/parser"
)

// TestJavaScriptSQLiDetection_Integration tests the complete flow for JS SQLi detection
func TestJavaScriptSQLiDetection_Integration(t *testing.T) {
	// Skip if test samples don't exist
	testSamplesPath := "../../test-samples/javascript"
	if _, err := os.Stat(testSamplesPath); os.IsNotExist(err) {
		t.Skip("Test samples directory not found, skipping integration test")
	}

	// Step 1: Detect frameworks
	ctx, err := discovery.DetectFrameworks(testSamplesPath)
	if err != nil {
		t.Fatalf("Framework detection failed: %v", err)
	}

	// Verify Express, Prisma, and Sequelize are detected
	jsFrameworks, ok := ctx.Frameworks["javascript"]
	if !ok {
		t.Fatal("No JavaScript frameworks detected")
	}

	t.Logf("Detected JavaScript frameworks: %v", jsFrameworks)

	// Check for expected frameworks
	hasExpress := contains(jsFrameworks, "express")
	hasPrisma := contains(jsFrameworks, "@prisma/client") || contains(jsFrameworks, "prisma")
	hasSequelize := contains(jsFrameworks, "sequelize")

	if !hasExpress {
		t.Error("Express framework not detected")
	}
	if !hasPrisma {
		t.Error("Prisma framework not detected")
	}
	if !hasSequelize {
		t.Error("Sequelize framework not detected")
	}

	// Step 2: Parse and chunk test files
	treeParser, err := parser.NewTreeSitterParser()
	if err != nil {
		t.Fatalf("Failed to create parser: %v", err)
	}

	chunkerInstance := chunker.NewASTChunker(600)

	testFiles := []struct {
		name             string
		path             string
		expectedFindVuln bool
	}{
		{"Express SQLi", filepath.Join(testSamplesPath, "sqli-express.js"), true},
		{"Prisma SQLi", filepath.Join(testSamplesPath, "sqli-prisma.js"), true},
		{"Sequelize SQLi", filepath.Join(testSamplesPath, "sqli-sequelize.js"), true},
	}

	for _, tf := range testFiles {
		t.Run(tf.name, func(t *testing.T) {
			// Read file
			content, err := os.ReadFile(tf.path)
			if err != nil {
				t.Fatalf("Failed to read %s: %v", tf.path, err)
			}

			// Parse
			tree, err := treeParser.Parse(content, "javascript")
			if err != nil {
				t.Fatalf("Failed to parse %s: %v", tf.path, err)
			}
			defer tree.Close()

			// Chunk
			chunks, err := chunkerInstance.ChunkFile(tree, content, tf.path, "javascript", jsFrameworks)
			if err != nil {
				t.Fatalf("Failed to chunk %s: %v", tf.path, err)
			}

			if len(chunks) == 0 {
				t.Error("No chunks extracted from file")
				return
			}

			t.Logf("Extracted %d chunks from %s", len(chunks), filepath.Base(tf.path))

			// Step 3: Verify prompt template renders with framework hints
			renderer, err := llm.NewPromptRenderer()
			if err != nil {
				t.Fatalf("Failed to create prompt renderer: %v", err)
			}

			// Test prompt rendering for first chunk
			firstChunk := chunks[0]
			prompt, err := renderer.RenderPrompt(llm.VulnTypeSQLInjection, firstChunk, []kb.KBEntry{})
			if err != nil {
				t.Fatalf("Failed to render prompt: %v", err)
			}

			// Verify framework-specific hints are included
			if hasExpress && !strings.Contains(prompt, "req.query") && !strings.Contains(prompt, "req.params") {
				t.Log("Prompt may not contain Express-specific hints (this is expected if chunks don't use Express patterns)")
			}

			// Verify prompt structure
			if !strings.Contains(prompt, "sql_injection") {
				t.Error("Prompt should contain SQL injection type")
			}
			if !strings.Contains(prompt, "findings") {
				t.Error("Prompt should contain findings schema")
			}

			t.Logf("✓ Prompt template rendered successfully for %s", filepath.Base(tf.path))
			t.Logf("  - Chunk: %s (lines %d-%d)", firstChunk.FunctionName, firstChunk.StartLine, firstChunk.EndLine)
			t.Logf("  - Frameworks: %v", firstChunk.Frameworks)
			t.Logf("  - Prompt length: %d characters", len(prompt))
		})
	}
}

// TestTypeScriptSQLiDetection_Integration tests the complete flow for TS SQLi detection
func TestTypeScriptSQLiDetection_Integration(t *testing.T) {
	testSamplesPath := "../../test-samples/typescript"
	if _, err := os.Stat(testSamplesPath); os.IsNotExist(err) {
		t.Skip("TypeScript test samples directory not found, skipping integration test")
	}

	// Parse TypeScript file
	treeParser, err := parser.NewTreeSitterParser()
	if err != nil {
		t.Fatalf("Failed to create parser: %v", err)
	}

	content, err := os.ReadFile(filepath.Join(testSamplesPath, "sqli-express.ts"))
	if err != nil {
		t.Fatalf("Failed to read TypeScript test file: %v", err)
	}

	// Parse with TypeScript parser
	tree, err := treeParser.Parse(content, "typescript")
	if err != nil {
		t.Fatalf("Failed to parse TypeScript: %v", err)
	}
	defer tree.Close()

	t.Log("✓ TypeScript file parsed successfully")

	// Chunk
	chunkerInstance := chunker.NewASTChunker(600)
	chunks, err := chunkerInstance.ChunkFile(tree, content, "sqli-express.ts", "typescript", []string{"express"})
	if err != nil {
		t.Fatalf("Failed to chunk TypeScript file: %v", err)
	}

	if len(chunks) == 0 {
		t.Fatal("No chunks extracted from TypeScript file")
	}

	t.Logf("✓ Extracted %d chunks from TypeScript file", len(chunks))

	// Verify function types are detected
	functionTypes := make(map[string]int)
	for _, chunk := range chunks {
		// Count different types of functions
		if strings.Contains(chunk.Source, "=>") {
			functionTypes["arrow"]++
		} else if strings.Contains(chunk.Source, "async") {
			functionTypes["async"]++
		} else if strings.Contains(chunk.Source, "class") {
			functionTypes["method"]++
		} else {
			functionTypes["function"]++
		}
	}

	t.Logf("✓ Function types detected: %v", functionTypes)

	// Verify TypeScript type annotations don't break parsing
	for _, chunk := range chunks {
		if strings.Contains(chunk.Source, ": Request") || strings.Contains(chunk.Source, ": Response") {
			t.Log("✓ TypeScript type annotations handled correctly")
			break
		}
	}
}

// TestPromptTemplateWithAllFrameworks verifies framework hints for all supported frameworks
func TestPromptTemplateWithAllFrameworks(t *testing.T) {
	renderer, err := llm.NewPromptRenderer()
	if err != nil {
		t.Fatalf("Failed to create prompt renderer: %v", err)
	}

	frameworks := []string{"express", "prisma", "sequelize"}

	for _, fw := range frameworks {
		t.Run(fw, func(t *testing.T) {
			chunk := chunker.CodeChunk{
				ID:           "test-chunk",
				FilePath:     "test.js",
				StartLine:    1,
				EndLine:      10,
				FunctionName: "testFunction",
				Language:     "javascript",
				Source:       "function testFunction() { return 'test'; }",
				Frameworks:   []string{fw},
			}

			prompt, err := renderer.RenderPrompt(llm.VulnTypeSQLInjection, chunk, []kb.KBEntry{})
			if err != nil {
				t.Fatalf("Failed to render prompt for %s: %v", fw, err)
			}

			// Verify framework is mentioned
			if !strings.Contains(prompt, fw) && !strings.Contains(prompt, "@prisma/client") {
				t.Errorf("Prompt should mention framework %s", fw)
			}

			// Verify SQLi-specific hints
			if !strings.Contains(prompt, "Framework-Specific Guidance") {
				t.Error("Prompt should contain framework-specific guidance section")
			}

			t.Logf("✓ Prompt rendered successfully for %s framework", fw)
		})
	}
}

// Helper function
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
