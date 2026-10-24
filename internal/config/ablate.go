package config

import (
	"os"
	"strings"
)

// Ablated reports whether a pipeline component is switched off for an ablation
// run via DEEPGUARD_ABLATE (comma-separated: rag, frameworks, ast).
func Ablated(component string) bool {
	for _, c := range strings.Split(os.Getenv("DEEPGUARD_ABLATE"), ",") {
		if strings.TrimSpace(c) == component {
			return true
		}
	}
	return false
}
