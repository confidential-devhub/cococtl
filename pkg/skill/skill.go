// Package skill embeds the cococtl agent skill (SKILL.md) so it can be shipped
// inside the binary and emitted with `cococtl skill`.
package skill

import _ "embed"

// Content is the embedded SKILL.md, teaching an AI coding agent the CoCo-fy
// workflow. Emitted verbatim by the `cococtl skill` command.
//
//go:embed SKILL.md
var Content string
