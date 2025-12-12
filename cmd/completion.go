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
	Long: `Generate shell completion script for kubectl-coco.

BASH

Prerequisites:

Install bash-completion.

For MacOS:
  $ brew install bash-completion@2

  # Add to your ~/.bash_profile:
  $ echo '[[ -r "/opt/homebrew/etc/profile.d/bash_completion.sh" ]] && . "/opt/homebrew/etc/profile.d/bash_completion.sh"' >> ~/.bash_profile

  # Reload profile:
  $ source ~/.bash_profile

For Linux:
  # Ubuntu/Debian:
  $ apt-get install bash-completion

  # CentOS/RHEL:
  $ yum install bash-completion

Installation:

For current session:
  $ source <(kubectl-coco completion bash)

For all sessions (permanent):
  # MacOS:
  $ kubectl-coco completion bash > $(brew --prefix)/etc/bash_completion.d/kubectl-coco

  # Linux:
  $ kubectl-coco completion bash > /etc/bash_completion.d/kubectl-coco

  # Then restart your shell

For kubectl plugin (kubectl coco):

Install kubectl completion first:
  # MacOS:
  $ kubectl completion bash > $(brew --prefix)/etc/bash_completion.d/kubectl

  # Linux:
  $ kubectl completion bash > /etc/bash_completion.d/kubectl

ZSH

Enable completion if not already enabled:
  $ echo "autoload -U compinit; compinit" >> ~/.zshrc

Install kubectl-coco completion:
  $ kubectl-coco completion zsh > "${fpath[1]}/_kubectl-coco"

Start a new shell for completion to take effect.
`,
	DisableFlagsInUseLine: true,
	ValidArgs:             []string{"bash", "zsh"},
	Args:                  cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
	RunE: func(_ *cobra.Command, args []string) error {
		switch args[0] {
		case "bash":
			return genBashCompletionWithPlugin(os.Stdout)
		case "zsh":
			return genZshCompletionWithPlugin(os.Stdout)
		}
		return nil
	},
}

func genBashCompletionWithPlugin(out io.Writer) error {
	// Generate standard completion
	buf := new(bytes.Buffer)
	if err := rootCmd.GenBashCompletion(buf); err != nil {
		return err
	}

	completion := buf.String()

	// Find the last "if [[ $(type -t compopt)" block and remove it
	// We'll replace it with our own that includes kubectl_coco
	lastIfIdx := strings.LastIndex(completion, "if [[ $(type -t compopt)")
	if lastIfIdx > 0 {
		// Find the start of this line
		lineStart := strings.LastIndex(completion[:lastIfIdx], "\n")
		if lineStart < 0 {
			lineStart = 0
		} else {
			lineStart++ // Move past the newline
		}
		completion = completion[:lineStart]
	}

	// Write the modified completion
	if _, err := fmt.Fprint(out, completion); err != nil {
		return err
	}

	// Add kubectl plugin completion (kubectl coco and kubectl-coco)
	pluginCompletion := `
# kubectl plugin completion
if [[ $(type -t compopt) = "builtin" ]]; then
    complete -o default -F __start_kubectl-coco kubectl-coco kubectl_coco
else
    complete -o default -o nospace -F __start_kubectl-coco kubectl-coco kubectl_coco
fi

# ex: ts=4 sw=4 et filetype=sh
`
	_, err := fmt.Fprint(out, pluginCompletion)
	return err
}

func genZshCompletionWithPlugin(out io.Writer) error {
	// Generate standard completion
	buf := new(bytes.Buffer)
	if err := rootCmd.GenZshCompletion(buf); err != nil {
		return err
	}

	completion := buf.String()

	// Replace both compdef lines to include kubectl_coco for plugin support
	// 1. #compdef directive (line 1) - used when file is in fpath
	completion = strings.Replace(completion, "#compdef kubectl-coco", "#compdef kubectl-coco kubectl_coco", 1)
	// 2. compdef command - used when sourcing file directly
	completion = strings.Replace(completion, "compdef _kubectl-coco kubectl-coco", "compdef _kubectl-coco kubectl-coco kubectl_coco", 1)

	// Write the modified completion
	_, err := fmt.Fprint(out, completion)
	return err
}

func init() {
	rootCmd.AddCommand(completionCmd)
}
