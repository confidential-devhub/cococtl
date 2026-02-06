// Package cmd provides the command-line interface for kubectl-coco.
package cmd

import (
	"context"
	"fmt"
	"os/exec"

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

// contextKey is the type for context keys used in cococtl
type contextKey int

const kubectlAvailableKey contextKey = iota

// detectKubectl checks if kubectl is available in PATH and caches the result in context
func detectKubectl(ctx context.Context) context.Context {
	_, err := exec.LookPath("kubectl")
	return context.WithValue(ctx, kubectlAvailableKey, err == nil)
}

// isKubectlAvailable retrieves the cached kubectl availability from context
func isKubectlAvailable(ctx context.Context) bool {
	if v := ctx.Value(kubectlAvailableKey); v != nil {
		return v.(bool)
	}
	return false
}

// requireKubectl returns an error if kubectl is not available, providing installation guidance
func requireKubectl(ctx context.Context, operation string) error {
	if !isKubectlAvailable(ctx) {
		return fmt.Errorf("kubectl is required for %s operations\n\n"+
			"To fix:\n"+
			"  1. Install kubectl: https://kubernetes.io/docs/tasks/tools/\n"+
			"  2. Ensure kubectl is in your PATH\n"+
			"  3. Verify with: kubectl version --client", operation)
	}
	return nil
}
