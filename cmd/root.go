package cmd

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "kubectl-coco",
	Short: "A kubectl plugin to deploy confidential containers (CoCo)",
	Long: `kubectl-coco is a kubectl plugin that helps you transform and deploy
Kubernetes manifests for Confidential Containers (CoCo).

It provides commands to:
  - Create CoCo configuration
  - Transform regular K8s manifests to CoCo-enabled manifests
  - Deploy CoCo applications`,
	Version: "0.1.0",
}

// Execute runs the root command
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	cobra.OnInitialize()
}

// getCurrentNamespace gets the current namespace from kubectl config
func getCurrentNamespace() (string, error) {
	ctx := context.Background()
	cmd := exec.CommandContext(ctx, "kubectl", "config", "view", "--minify", "-o", "jsonpath={..namespace}")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get current namespace: %w", err)
	}

	namespace := strings.TrimSpace(string(output))
	if namespace == "" {
		namespace = "default"
	}

	return namespace, nil
}
