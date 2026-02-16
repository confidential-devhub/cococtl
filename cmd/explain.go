package cmd

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/confidential-devhub/cococtl/pkg/config"
	"github.com/confidential-devhub/cococtl/pkg/examples"
	"github.com/confidential-devhub/cococtl/pkg/explain"
	"github.com/spf13/cobra"
)

var explainCmd = &cobra.Command{
	Use:   "explain",
	Short: "Explain CoCo transformations without applying",
	Long: `Analyze and explain what transformations would be applied to convert
a regular Kubernetes manifest to a CoCo-enabled manifest.

This command is purely educational and does not require a cluster connection.
It helps you understand what changes are made to enable Confidential Containers.

Supports both local files and remote URLs (http/https).

Examples:
  # Explain transformations on your manifest
  kubectl coco explain -f app.yaml

  # Explain from remote URL
  kubectl coco explain -f https://raw.githubusercontent.com/user/repo/main/app.yaml

  # Use a built-in example
  kubectl coco explain --example simple-pod
  kubectl coco explain --example deployment-secrets
  kubectl coco explain --example sidecar-service

  # List available examples
  kubectl coco explain --list-examples

  # Different output formats
  kubectl coco explain -f app.yaml --format diff
  kubectl coco explain -f app.yaml --format markdown > TRANSFORMATIONS.md

  # Enable sidecar to see sidecar transformation
  kubectl coco explain -f app.yaml --sidecar`,
	RunE: runExplain,
}

var (
	explainManifestFile  string
	explainExample       string
	explainFormat        string
	explainListExamples  bool
	explainConfigPath    string
	explainEnableSidecar bool
	explainSidecarPort   int
	explainOutput        string
)

func init() {
	rootCmd.AddCommand(explainCmd)

	explainCmd.Flags().StringVarP(&explainManifestFile, "filename", "f", "", "Path to Kubernetes manifest file or URL")
	explainCmd.Flags().StringVar(&explainExample, "example", "", "Use built-in example (simple-pod, deployment-secrets, sidecar-service)")
	explainCmd.Flags().StringVar(&explainFormat, "format", "text", "Output format: text, diff, markdown")
	explainCmd.Flags().BoolVar(&explainListExamples, "list-examples", false, "List available built-in examples")
	explainCmd.Flags().StringVar(&explainConfigPath, "config", "", "Path to CoCo config file (default: ~/.kube/coco-config.toml)")
	explainCmd.Flags().BoolVar(&explainEnableSidecar, "sidecar", false, "Show sidecar transformation")
	explainCmd.Flags().IntVar(&explainSidecarPort, "sidecar-port-forward", 0, "Port to forward via sidecar (auto-detected from Service if not specified)")
	explainCmd.Flags().StringVarP(&explainOutput, "output", "o", "", "Write output to file instead of stdout")
}

func runExplain(_ *cobra.Command, _ []string) error {
	// Handle --list-examples
	if explainListExamples {
		listExamples()
		return nil
	}

	// Determine manifest source
	var manifestPath string
	var manifestContent string
	var isExample bool
	var tempFile string

	if explainExample != "" {
		// Use built-in example
		ex := examples.Get(explainExample)
		if ex == nil {
			return fmt.Errorf("example %q not found. Use --list-examples to see available examples", explainExample)
		}

		fmt.Printf("📚 Using built-in example: %s\n", ex.Name)
		fmt.Printf("   %s\n\n", ex.Description)

		// Write example to temporary file for analysis
		tmpFile, err := os.CreateTemp("", "coco-example-*.yaml")
		if err != nil {
			return fmt.Errorf("failed to create temp file: %w", err)
		}
		defer func() {
			_ = os.Remove(tmpFile.Name()) // Best effort cleanup
		}()

		if _, err := tmpFile.WriteString(ex.Manifest); err != nil {
			return fmt.Errorf("failed to write example: %w", err)
		}
		if err := tmpFile.Close(); err != nil {
			return fmt.Errorf("failed to close temp file: %w", err)
		}

		manifestPath = tmpFile.Name()
		manifestContent = ex.Manifest
		isExample = true
	} else if explainManifestFile != "" {
		// Check if it's a remote URL
		if isRemoteFile(explainManifestFile) {
			fmt.Printf("📥 Downloading remote manifest: %s\n", explainManifestFile)
			var err error
			tempFile, err = downloadRemoteFile(explainManifestFile)
			if err != nil {
				return fmt.Errorf("failed to download remote manifest: %w", err)
			}
			defer func() {
				_ = os.Remove(tempFile)
			}()
			manifestPath = tempFile
			fmt.Printf("   Downloaded to: %s\n\n", tempFile)
		} else {
			// Use local file
			manifestPath = explainManifestFile
		}

		// Read manifest content
		// #nosec G304 - User-provided manifest file path is expected
		data, err := os.ReadFile(manifestPath)
		if err != nil {
			return fmt.Errorf("failed to read manifest: %w", err)
		}
		manifestContent = string(data)
	} else {
		return fmt.Errorf("either --filename or --example is required")
	}

	// Load configuration
	var cfg *config.CocoConfig
	var exampleConfigPath string

	if isExample && explainConfigPath == "" {
		// Use example config for built-in examples
		var err error
		exampleConfigPath, err = examples.GetExampleConfigPath()
		if err != nil {
			return fmt.Errorf("failed to create example config: %w", err)
		}
		defer func() {
			_ = os.Remove(exampleConfigPath) // Best effort cleanup
		}()

		cfg, err = config.Load(exampleConfigPath)
		if err != nil {
			return fmt.Errorf("failed to load example config: %w", err)
		}

		fmt.Printf("📋 Using example config: %s\n\n", exampleConfigPath)
	} else if explainConfigPath == "" {
		// Try to load user config
		var err error
		explainConfigPath, err = config.GetConfigPath()
		if err != nil {
			// Use default config if not found
			cfg = getDefaultConfig()
		} else {
			cfg, err = config.Load(explainConfigPath)
			if err != nil {
				fmt.Printf("⚠️  Warning: Could not load config (using defaults): %v\n", err)
				cfg = getDefaultConfig()
			}
		}
	} else {
		// User specified explicit config path
		var err error
		cfg, err = config.Load(explainConfigPath)
		if err != nil {
			fmt.Printf("⚠️  Warning: Could not load config (using defaults): %v\n", err)
			cfg = getDefaultConfig()
		}
	}

	// Perform analysis
	analysis, err := explain.Analyze(manifestPath, cfg, explainEnableSidecar, explainSidecarPort)
	if err != nil {
		return fmt.Errorf("failed to analyze manifest: %w", err)
	}

	// Update manifest path for display (use original filename for examples)
	if isExample {
		analysis.ManifestPath = explainExample + ".yaml"
	}

	// Format output
	var output string
	switch strings.ToLower(explainFormat) {
	case "text":
		output = explain.FormatText(analysis)
	case "diff":
		output = explain.FormatDiff(analysis)
	case "markdown", "md":
		output = explain.FormatMarkdown(analysis)
	default:
		return fmt.Errorf("unsupported format: %s (use: text, diff, markdown)", explainFormat)
	}

	// Show original manifest if it's an example
	if isExample {
		fmt.Println("📄 Original Manifest:")
		fmt.Println(strings.Repeat("─", 60))
		// Show first 20 lines
		lines := strings.Split(manifestContent, "\n")
		maxLines := 20
		if len(lines) < maxLines {
			maxLines = len(lines)
		}
		for i := 0; i < maxLines; i++ {
			fmt.Println(lines[i])
		}
		if len(lines) > maxLines {
			fmt.Printf("... (%d more lines)\n", len(lines)-maxLines)
		}
		fmt.Println(strings.Repeat("─", 60))
		fmt.Println()

		// Show learning points
		ex := examples.Get(explainExample)
		if len(ex.LearningPoints) > 0 {
			fmt.Println("🎓 Learning Points:")
			for _, point := range ex.LearningPoints {
				fmt.Printf("   • %s\n", point)
			}
			fmt.Println()
		}
	}

	// Write or print output
	if explainOutput != "" {
		if err := os.WriteFile(explainOutput, []byte(output), 0600); err != nil {
			return fmt.Errorf("failed to write output file: %w", err)
		}
		fmt.Printf("✅ Analysis written to: %s\n", explainOutput)
	} else {
		fmt.Println(output)
	}

	// Footer for examples
	if isExample {
		fmt.Println("💡 Try it yourself:")
		fmt.Printf("   kubectl coco explain --list-examples\n")
		fmt.Printf("   kubectl coco explain -f your-app.yaml\n")
	}

	return nil
}

func listExamples() {
	fmt.Println("📚 Available Built-in Examples:")

	// Get and sort example names
	names := examples.List()
	sort.Strings(names)

	for _, name := range names {
		ex := examples.Get(name)
		fmt.Printf("• %s\n", name)
		fmt.Printf("  %s\n", ex.Description)
		fmt.Printf("  Scenario: %s\n", ex.Scenario)
		if len(ex.LearningPoints) > 0 {
			fmt.Printf("  Learning: %s\n", ex.LearningPoints[0])
		}
		fmt.Println()
	}

	fmt.Println("Usage:")
	fmt.Println("  kubectl coco explain --example <name>")
	fmt.Println("\nExample:")
	fmt.Println("  kubectl coco explain --example simple-pod")
}

func getDefaultConfig() *config.CocoConfig {
	return &config.CocoConfig{
		TrusteeServer: "http://trustee-kbs.default.svc.cluster.local:8080",
		RuntimeClass:  "kata-cc",
		Sidecar: config.SidecarConfig{
			HTTPSPort: 8443,
			Image:     "ghcr.io/confidential-containers/sidecar:latest",
		},
	}
}
