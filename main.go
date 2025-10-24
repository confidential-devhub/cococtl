package main

import (
	"os"

	"github.com/confidential-containers/coco-ctl/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
