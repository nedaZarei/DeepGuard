package config

import "testing"

func TestAblated(t *testing.T) {
	t.Setenv("DEEPGUARD_ABLATE", "rag, ast")
	if !Ablated("rag") || !Ablated("ast") || Ablated("frameworks") {
		t.Fatal("wrong components reported as ablated")
	}
	t.Setenv("DEEPGUARD_ABLATE", "")
	if Ablated("rag") {
		t.Fatal("nothing should be ablated when unset")
	}
}
