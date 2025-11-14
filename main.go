// kubectl-coco is a kubectl plugin for deploying Confidential Containers.
package main

import (
	"os"

	"github.com/confidential-devhub/cococtl/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
