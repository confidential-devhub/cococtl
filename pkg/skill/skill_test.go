package skill

import (
	"strings"
	"testing"
)

// TestContentEmbedded is the ponytail self-check: if the embed breaks or the
// file is renamed/emptied, this fails instead of shipping an empty `cococtl skill`.
func TestContentEmbedded(t *testing.T) {
	if strings.TrimSpace(Content) == "" {
		t.Fatal("embedded SKILL.md is empty")
	}
	if !strings.Contains(Content, "name: cocofy") {
		t.Error("embedded SKILL.md missing frontmatter 'name: cocofy'")
	}
}
