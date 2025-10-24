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
