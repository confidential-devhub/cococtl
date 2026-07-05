package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/confidential-devhub/cococtl/pkg/skill"
)

var skillCmd = &cobra.Command{
	Use:   "skill",
	Short: "Print the cococtl agent skill (SKILL.md) to stdout",
	Long: `Print the embedded cococtl agent skill to stdout.

The skill teaches an AI coding agent (e.g. Claude Code) the full
init -> apply -> populate -> deploy workflow for CoCo-fying an app.

Install it for your agent by redirecting into your skills directory:

  mkdir -p ~/.claude/skills/cocofy
  cococtl skill > ~/.claude/skills/cocofy/SKILL.md
`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		_, err := fmt.Fprint(cmd.OutOrStdout(), skill.Content)
		return err
	},
}

func init() {
	rootCmd.AddCommand(skillCmd)
}
