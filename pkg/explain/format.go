package explain

import (
	"fmt"
	"strings"
)

// FormatText generates a human-readable text explanation.
func FormatText(analysis *Analysis) string {
	var out strings.Builder

	// Header
	out.WriteString("📋 Analyzing manifest")
	if analysis.ManifestPath != "" {
		out.WriteString(fmt.Sprintf(": %s", analysis.ManifestPath))
	}
	out.WriteString("\n\n")

	// Resource info
	out.WriteString("🔍 Detected Resources:\n")
	out.WriteString(fmt.Sprintf("  - %s: %s\n", analysis.ResourceKind, analysis.ResourceName))
	if analysis.HasService {
		out.WriteString(fmt.Sprintf("  - Service (port %d)\n", analysis.ServicePort))
	}
	out.WriteString("\n")

	// Transformations
	out.WriteString("📝 Transformations Required:\n\n")

	for i, t := range analysis.Transformations {
		out.WriteString(fmt.Sprintf("%d. %s\n", i+1, t.Name))
		out.WriteString(strings.Repeat("━", 60))
		out.WriteString("\n")

		// Before/After
		if t.Before != "" {
			out.WriteString("Before: ")
			out.WriteString(indentMultiline(t.Before, "        "))
			out.WriteString("\n\n")
		}

		if t.After != "" {
			out.WriteString("After:  ")
			out.WriteString(indentMultiline(t.After, "        "))
			out.WriteString("\n\n")
		}

		// Why
		if t.Reason != "" {
			out.WriteString(fmt.Sprintf("ℹ️  Why: %s\n", t.Reason))
		}

		// Details
		if len(t.Details) > 0 {
			for _, detail := range t.Details {
				out.WriteString(fmt.Sprintf("ℹ️  %s\n", detail))
			}
		}

		out.WriteString("\n")
	}

	// Summary
	out.WriteString("✅ Summary:\n")
	out.WriteString(fmt.Sprintf("   - %d transformation(s) applied\n", len(analysis.Transformations)))
	if analysis.SecretCount > 0 {
		out.WriteString(fmt.Sprintf("   - %d secret(s) converted to sealed format\n", analysis.SecretCount))
	}
	if analysis.SidecarEnabled {
		out.WriteString("   - Sidecar container injected for secure access\n")
	}
	out.WriteString("   - Ready for CoCo deployment\n")

	return out.String()
}

// FormatDiff generates a side-by-side diff view.
func FormatDiff(analysis *Analysis) string {
	var out strings.Builder

	out.WriteString(fmt.Sprintf("Manifest: %s → %s (CoCo-enabled)\n\n",
		analysis.ManifestPath, strings.TrimSuffix(analysis.ManifestPath, ".yaml")+"-coco.yaml"))

	for _, t := range analysis.Transformations {
		out.WriteString(fmt.Sprintf("━━━ %s ━━━\n", t.Name))
		out.WriteString(formatSideBySide(t.Before, t.After))
		out.WriteString("\n")
		if t.Reason != "" {
			out.WriteString(fmt.Sprintf("💡 %s\n\n", t.Reason))
		}
	}

	return out.String()
}

// FormatMarkdown generates markdown documentation.
func FormatMarkdown(analysis *Analysis) string {
	var out strings.Builder

	out.WriteString(fmt.Sprintf("# CoCo Transformation Analysis: %s\n\n", analysis.ResourceName))

	// Resource info
	out.WriteString("## 📋 Resources\n\n")
	out.WriteString(fmt.Sprintf("- **Kind**: %s\n", analysis.ResourceKind))
	out.WriteString(fmt.Sprintf("- **Name**: %s\n", analysis.ResourceName))
	if analysis.HasService {
		out.WriteString(fmt.Sprintf("- **Service Port**: %d\n", analysis.ServicePort))
	}
	out.WriteString("\n")

	// Transformations
	out.WriteString("## 📝 Transformations\n\n")

	for i, t := range analysis.Transformations {
		out.WriteString(fmt.Sprintf("### %d. %s\n\n", i+1, t.Name))
		out.WriteString(fmt.Sprintf("**Description**: %s\n\n", t.Description))

		if t.Reason != "" {
			out.WriteString(fmt.Sprintf("**Why**: %s\n\n", t.Reason))
		}

		if t.Before != "" {
			out.WriteString("**Before**:\n```yaml\n")
			out.WriteString(t.Before)
			out.WriteString("\n```\n\n")
		}

		if t.After != "" {
			out.WriteString("**After**:\n```yaml\n")
			out.WriteString(t.After)
			out.WriteString("\n```\n\n")
		}

		if len(t.Details) > 0 {
			out.WriteString("**Details**:\n")
			for _, detail := range t.Details {
				out.WriteString(fmt.Sprintf("- %s\n", detail))
			}
			out.WriteString("\n")
		}
	}

	// Summary
	out.WriteString("## ✅ Summary\n\n")
	out.WriteString(fmt.Sprintf("- **Total Transformations**: %d\n", len(analysis.Transformations)))
	if analysis.SecretCount > 0 {
		out.WriteString(fmt.Sprintf("- **Secrets Converted**: %d\n", analysis.SecretCount))
	}
	if analysis.SidecarEnabled {
		out.WriteString("- **Sidecar**: Enabled\n")
	}

	return out.String()
}

// Helper functions

func indentMultiline(text, indent string) string {
	lines := strings.Split(text, "\n")
	for i := range lines {
		if i > 0 {
			lines[i] = indent + lines[i]
		}
	}
	return strings.Join(lines, "\n")
}

func formatSideBySide(before, after string) string {
	var out strings.Builder

	beforeLines := strings.Split(before, "\n")
	afterLines := strings.Split(after, "\n")

	maxLen := len(beforeLines)
	if len(afterLines) > maxLen {
		maxLen = len(afterLines)
	}

	// Column headers
	out.WriteString("BEFORE                              │ AFTER\n")
	out.WriteString(strings.Repeat("─", 36) + "┼" + strings.Repeat("─", 40) + "\n")

	for i := 0; i < maxLen; i++ {
		var beforeLine, afterLine string
		if i < len(beforeLines) {
			beforeLine = beforeLines[i]
		}
		if i < len(afterLines) {
			afterLine = afterLines[i]
		}

		// Truncate or pad before line to 35 chars
		if len(beforeLine) > 35 {
			beforeLine = beforeLine[:32] + "..."
		}
		beforeLine = fmt.Sprintf("%-35s", beforeLine)

		out.WriteString(fmt.Sprintf("%s │ %s\n", beforeLine, afterLine))
	}

	return out.String()
}
