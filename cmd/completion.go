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

PREREQUISITES:

  Bash requires bash-completion to be installed:
    macOS: brew install bash-completion@2
    Linux: Usually pre-installed (apt-get/yum install bash-completion)

  Add to your ~/.bash_profile (macOS):
    [[ -r "/opt/homebrew/etc/profile.d/bash_completion.sh" ]] && . "/opt/homebrew/etc/profile.d/bash_completion.sh"

BASH:

  Current session:
    $ source <(kubectl-coco completion bash)

  Permanent:
    $ kubectl-coco completion bash > $(brew --prefix)/etc/bash_completion.d/kubectl-coco
    $ source ~/.bash_profile

ZSH:

  Install completion:
    $ kubectl-coco completion zsh > "${fpath[1]}/_kubectl-coco"
    $ exec zsh

KUBECTL PLUGIN:

  For 'kubectl coco' completion, install kubectl completion:
    $ kubectl completion bash > $(brew --prefix)/etc/bash_completion.d/kubectl
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

	// Find and remove the last compdef line
	lastCompdefIdx := strings.LastIndex(completion, "compdef _kubectl-coco kubectl-coco")
	if lastCompdefIdx > 0 {
		// Find the start of this line
		lineStart := strings.LastIndex(completion[:lastCompdefIdx], "\n")
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
compdef _kubectl-coco kubectl-coco kubectl_coco
`
	_, err := fmt.Fprint(out, pluginCompletion)
	return err
}

func init() {
	rootCmd.AddCommand(completionCmd)
}
