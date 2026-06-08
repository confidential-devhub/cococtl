// Package cmd provides the command-line interface for cococtl / kubectl-coco.
package cmd

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/confidential-devhub/cococtl/cmd/initdata"
	"github.com/confidential-devhub/cococtl/cmd/kbs"
)

// version is set at build time via ldflags
var version = "dev"

var rootCmd = &cobra.Command{
	Use:   "cococtl",
	Short: "Deploy and manage Confidential Containers (CoCo) applications",
	Long: `cococtl (also usable as kubectl-coco) transforms and deploys
Kubernetes manifests for Confidential Containers (CoCo).

It provides commands to:
  - Create CoCo configuration
  - Transform regular K8s manifests to CoCo-enabled manifests
  - Deploy CoCo applications`,
	Version:      version,
	SilenceUsage: true,
}

// Execute runs the root command
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	// Adopt the correct command name based on how the binary is invoked.
	// Supports both standalone usage ("cococtl") and kubectl plugin usage ("kubectl-coco").
	name := filepath.Base(os.Args[0])
	if name == "kubectl-coco" {
		rootCmd.Use = "kubectl-coco"
	}

	cobra.OnInitialize()
	rootCmd.AddCommand(kbs.KbsCmd)
	rootCmd.AddCommand(initdata.InitdataCmd)
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
