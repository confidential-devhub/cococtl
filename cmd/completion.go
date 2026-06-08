package cmd

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var completionCmd = &cobra.Command{
	Use:   "completion [bash|zsh]",
	Short: "Generate shell completion script",
	Long: `Generate shell completion script for cococtl / kubectl-coco.

HOW COMPLETION WORKS

There are two independent completion mechanisms:

  1. Generated script  — covers 'cococtl' and 'kubectl-coco'.
                         Source this file once (see below).

  2. kubectl plugin    — covers 'kubectl coco <TAB>'. kubectl calls the
                         kubectl_complete-coco binary directly; no generated
                         script is involved. Requires:
                           a) kubectl's own completion to be set up, AND
                           b) kubectl_complete-coco in PATH (make install
                              creates this symlink automatically).

BASH

Prerequisites (skip if already done):

  # macOS
  $ brew install bash-completion@2
  $ echo '[[ -r "/opt/homebrew/etc/profile.d/bash_completion.sh" ]] && . "/opt/homebrew/etc/profile.d/bash_completion.sh"' >> ~/.bash_profile
  $ source ~/.bash_profile

  # Linux (Ubuntu/Debian)
  $ apt-get install bash-completion

For current session only:
  $ source <(cococtl completion bash)

Permanent installation:
  # macOS
  $ cococtl completion bash > $(brew --prefix)/etc/bash_completion.d/cococtl

  # Linux — system-wide (requires root)
  $ cococtl completion bash | sudo tee /etc/bash_completion.d/cococtl > /dev/null

  # Linux — current user only (no sudo required)
  $ mkdir -p ~/.local/share/bash-completion/completions
  $ cococtl completion bash > ~/.local/share/bash-completion/completions/cococtl

  # Then restart your shell

For 'kubectl coco <TAB>' — set up kubectl's own completion (once):
  # macOS
  $ kubectl completion bash > $(brew --prefix)/etc/bash_completion.d/kubectl

  # Linux — system-wide
  $ kubectl completion bash | sudo tee /etc/bash_completion.d/kubectl > /dev/null

  # Linux — current user only
  $ kubectl completion bash > ~/.local/share/bash-completion/completions/kubectl

  Then verify the symlink is in PATH:
  $ which kubectl_complete-coco   # should resolve to cococtl

ZSH

Enable completion if not already enabled:
  $ echo "autoload -U compinit; compinit" >> ~/.zshrc

Install completion (covers cococtl and kubectl-coco):
  $ cococtl completion zsh > "${fpath[1]}/_cococtl"

For 'kubectl coco <TAB>' — set up kubectl's own zsh completion (once):
  $ kubectl completion zsh > "${fpath[1]}/_kubectl"

  Then verify the symlink is in PATH:
  $ which kubectl_complete-coco   # should resolve to cococtl

  Start a new shell for all changes to take effect.
`,
	DisableFlagsInUseLine: true,
	ValidArgs:             []string{"bash", "zsh"},
	Args:                  cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
	RunE: func(_ *cobra.Command, args []string) error {
		switch args[0] {
		case "bash":
			return genBashCompletionWithAliases(os.Stdout)
		case "zsh":
			return genZshCompletionWithAliases(os.Stdout)
		}
		return nil
	},
}

// genBashCompletionWithAliases generates bash completion for the primary command
// name (from rootCmd.Use) and appends alias registrations for the alternate name.
func genBashCompletionWithAliases(out io.Writer) error {
	// Cobra generates completion using rootCmd.Use as the function/command name.
	if err := rootCmd.GenBashCompletion(out); err != nil {
		return err
	}

	// Determine the __start_<name> function cobra registered above.
	startFn := "__start_" + rootCmd.Use

	// Register the alternate invocation name to the same function.
	var alts []string
	if rootCmd.Use == "cococtl" {
		alts = []string{"kubectl-coco"}
	} else {
		alts = []string{"cococtl"}
	}

	aliasBlock := fmt.Sprintf(`
# Completions for alternate invocation names
if [[ $(type -t compopt) = "builtin" ]]; then
    complete -o default -F %s %s
else
    complete -o default -o nospace -F %s %s
fi

# ex: ts=4 sw=4 et filetype=sh
`, startFn, strings.Join(alts, " "), startFn, strings.Join(alts, " "))

	_, err := fmt.Fprint(out, aliasBlock)
	return err
}

// genZshCompletionWithAliases generates zsh completion and expands the compdef
// directives to include the alternate invocation names.
func genZshCompletionWithAliases(out io.Writer) error {
	buf := new(bytes.Buffer)
	if err := rootCmd.GenZshCompletion(buf); err != nil {
		return err
	}

	use := rootCmd.Use

	var alts []string
	if use == "cococtl" {
		alts = []string{"kubectl-coco"}
	} else {
		alts = []string{"cococtl"}
	}
	altsStr := strings.Join(alts, " ")

	completion := buf.String()

	// Cobra writes two compdef lines; expand both to include the alias names.
	// Line 1: #compdef <use>
	// Line 2: compdef _<use> <use>
	completion = strings.Replace(completion, "#compdef "+use, "#compdef "+use+" "+altsStr, 1)
	completion = strings.Replace(completion, "compdef _"+use+" "+use, "compdef _"+use+" "+use+" "+altsStr, 1)

	_, err := fmt.Fprint(out, completion)
	return err
}

func init() {
	rootCmd.AddCommand(completionCmd)
}
