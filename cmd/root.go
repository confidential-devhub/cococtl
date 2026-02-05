// Package cmd provides the command-line interface for kubectl-coco.
package cmd

import (
	"github.com/spf13/cobra"
)

// version is set at build time via ldflags
var version = "dev"

var rootCmd = &cobra.Command{
	Use:   "kubectl-coco",
	Short: "A kubectl plugin to deploy confidential containers (CoCo)",
	Long: `kubectl-coco is a kubectl plugin that helps you transform and deploy
Kubernetes manifests for Confidential Containers (CoCo).

It provides commands to:
  - Create CoCo configuration
  - Transform regular K8s manifests to CoCo-enabled manifests
  - Deploy CoCo applications`,
	Version: version,
}

// Execute runs the root command
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	cobra.OnInitialize()
}
