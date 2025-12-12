// kubectl-coco is a kubectl plugin for deploying Confidential Containers.
package main

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/confidential-devhub/cococtl/cmd"
)

func main() {
	// Handle kubectl plugin completion
	// When kubectl calls kubectl_complete-coco, it doesn't pass __complete
	// but cobra needs it to trigger completion mode
	binaryName := filepath.Base(os.Args[0])
	if strings.Contains(binaryName, "kubectl_complete-") {
		// Inject __complete as the first argument
		os.Args = append([]string{os.Args[0], "__complete"}, os.Args[1:]...)
	}

	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
