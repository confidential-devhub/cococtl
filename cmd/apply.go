package cmd

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/confidential-devhub/cococtl/pkg/config"
	"github.com/confidential-devhub/cococtl/pkg/initdata"
	"github.com/confidential-devhub/cococtl/pkg/manifest"
	"github.com/spf13/cobra"
)

const (
	defaultInitContainerImage = "quay.io/fedora/fedora:44"
)

var applyCmd = &cobra.Command{
	Use:   "apply",
	Short: "Transform and apply a Kubernetes manifest for CoCo",
	Long: `Transform a regular Kubernetes manifest to a CoCo-enabled manifest and apply it.

This command will:
  1. Load the specified manifest
  2. Add/update RuntimeClass
  3. Add initdata annotation
  4. Add first initContainer for attestation (if requested)
  5. Save a backup of the transformed manifest (*-coco.yaml)
  6. Apply the transformed manifest using kubectl

Example:
  kubectl coco apply -f app.yaml
  kubectl coco apply -f app.yaml --runtime-class kata-remote
  kubectl coco apply -f app.yaml --init-container`,
	RunE: runApply,
}

var (
	manifestFile     string
	runtimeClass     string
	addInitContainer bool
	initContainerImg string
	initContainerCmd string
	skipApply        bool
	configPath       string
)

func init() {
	rootCmd.AddCommand(applyCmd)

	applyCmd.Flags().StringVarP(&manifestFile, "filename", "f", "", "Path to Kubernetes manifest file (required)")
	applyCmd.Flags().StringVar(&runtimeClass, "runtime-class", "", "RuntimeClass to use (default from config)")
	applyCmd.Flags().BoolVar(&addInitContainer, "init-container", false, "Add default attestation initContainer")
	applyCmd.Flags().StringVar(&initContainerImg, "init-container-img", "", "Custom init container image (requires --init-container)")
	applyCmd.Flags().StringVar(&initContainerCmd, "init-container-cmd", "", "Custom init container command (requires --init-container)")
	applyCmd.Flags().BoolVar(&skipApply, "skip-apply", false, "Skip kubectl apply, only transform the manifest")
	applyCmd.Flags().StringVar(&configPath, "config", "", "Path to CoCo config file (default: ~/.kube/coco-config.toml)")

	applyCmd.MarkFlagRequired("filename")
}

func runApply(cmd *cobra.Command, args []string) error {
	// Load configuration
	if configPath == "" {
		var err error
		configPath, err = config.GetConfigPath()
		if err != nil {
			return fmt.Errorf("failed to get config path: %w", err)
		}
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config (run 'kubectl coco init' first): %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	// Determine runtime class to use
	rc := runtimeClass
	if rc == "" {
		// Use default from config
		rc = cfg.RuntimeClass
	}

	// Load manifest
	fmt.Printf("Loading manifest: %s\n", manifestFile)
	m, err := manifest.Load(manifestFile)
	if err != nil {
		return fmt.Errorf("failed to load manifest: %w", err)
	}

	fmt.Printf("Transforming %s '%s' for CoCo...\n", m.GetKind(), m.GetName())

	// Validate initContainer flags
	if (initContainerImg != "" || initContainerCmd != "") && !addInitContainer {
		return fmt.Errorf("--init-container-img and --init-container-cmd require --init-container flag")
	}

	// Transform manifest
	if err := transformManifest(m, cfg, rc); err != nil {
		return fmt.Errorf("failed to transform manifest: %w", err)
	}

	// Create backup
	backupPath, err := m.Backup()
	if err != nil {
		return fmt.Errorf("failed to create backup: %w", err)
	}
	fmt.Printf("Backup saved to: %s\n", backupPath)

	// Apply manifest if not skipped
	if !skipApply {
		fmt.Println("Applying manifest with kubectl...")
		if err := applyWithKubectl(backupPath); err != nil {
			return fmt.Errorf("failed to apply manifest: %w", err)
		}
		fmt.Println("Successfully applied!")
	} else {
		fmt.Println("Skipping kubectl apply (use --skip-apply=false to apply)")
	}

	return nil
}

func transformManifest(m *manifest.Manifest, cfg *config.CocoConfig, rc string) error {
	// 1. Set RuntimeClass
	fmt.Printf("  - Setting runtimeClassName: %s\n", rc)
	if err := m.SetRuntimeClass(rc); err != nil {
		return fmt.Errorf("failed to set runtime class: %w", err)
	}

	// 2. Add initContainer if requested
	if addInitContainer {
		if err := handleInitContainer(m, cfg); err != nil {
			return fmt.Errorf("failed to add initContainer: %w", err)
		}
	}

	// 3. Warn about secrets (will be replaced with automatic conversion)
	secretRefs := m.GetSecretRefs()
	if len(secretRefs) > 0 {
		fmt.Printf("  ⚠ Warning: Found %d secret reference(s) in manifest: %v\n", len(secretRefs), secretRefs)
		fmt.Println("    Secrets should be converted to sealed secrets for CoCo.")
	}

	// 4. Generate and add initdata annotation
	fmt.Println("  - Generating initdata annotation")
	initdataValue, err := initdata.Generate(cfg)
	if err != nil {
		return fmt.Errorf("failed to generate initdata: %w", err)
	}

	if err := m.SetAnnotation("io.katacontainers.config.hypervisor.cc_init_data", initdataValue); err != nil {
		return fmt.Errorf("failed to set initdata annotation: %w", err)
	}

	// 5. Add custom annotations from config
	if len(cfg.Annotations) > 0 {
		fmt.Println("  - Adding custom annotations from config")
		for key, value := range cfg.Annotations {
			// Only add annotations with non-empty values
			if value != "" {
				fmt.Printf("    %s: %s\n", key, value)
				if err := m.SetAnnotation(key, value); err != nil {
					return fmt.Errorf("failed to set annotation %s: %w", key, err)
				}
			}
		}
	}

	return nil
}

func handleInitContainer(m *manifest.Manifest, cfg *config.CocoConfig) error {
	// Determine the image to use
	image := initContainerImg
	if image == "" {
		// Use configured init container image or default
		if cfg.InitContainerImage != "" {
			image = cfg.InitContainerImage
		} else {
			image = defaultInitContainerImage // Default image
		}
	}

	// Determine the command to use
	var command []string
	if initContainerCmd != "" {
		// User provided custom command via CLI
		command = []string{"sh", "-c", initContainerCmd}
	} else if cfg.InitContainerCmd != "" {
		// Use configured init container command
		command = []string{"sh", "-c", cfg.InitContainerCmd}
	} else {
		// Default attestation check command
		command = []string{
			"sh",
			"-c",
			"curl http://localhost:8006/cdh/resource/default/attestation-status/status",
		}
	}

	fmt.Printf("  - Adding initContainer 'get-attn-status' (image: %s)\n", image)
	if err := m.AddInitContainer("get-attn-status", image, command); err != nil {
		return fmt.Errorf("failed to add initContainer: %w", err)
	}

	return nil
}

func applyWithKubectl(manifestPath string) error {
	cmd := exec.Command("kubectl", "apply", "-f", manifestPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("kubectl apply failed: %w", err)
	}

	return nil
}
