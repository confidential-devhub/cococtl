package cmd

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/confidential-containers/coco-ctl/pkg/config"
	"github.com/confidential-containers/coco-ctl/pkg/initdata"
	"github.com/confidential-containers/coco-ctl/pkg/manifest"
	"github.com/confidential-containers/coco-ctl/pkg/sealed"
	"github.com/spf13/cobra"
)

var applyCmd = &cobra.Command{
	Use:   "apply",
	Short: "Transform and apply a Kubernetes manifest for CoCo",
	Long: `Transform a regular Kubernetes manifest to a CoCo-enabled manifest and apply it.

This command will:
  1. Load the specified manifest
  2. Add/update RuntimeClass
  3. Convert K8s secrets to sealed secrets (if present)
  4. Add initdata annotation
  5. Add first initContainer for attestation
  6. Save a backup of the transformed manifest (*-coco.yaml)
  7. Apply the transformed manifest using kubectl

Example:
  kubectl coco apply -f app.yaml
  kubectl coco apply -f app.yaml --runtime-class kata-remote
  kubectl coco apply -f app.yaml --init-container myimage:latest`,
	RunE: runApply,
}

var (
	manifestFile     string
	runtimeClass     string
	addInitContainer bool
	initContainerImg string
	initContainerCmd string
	resourceURI      string
	secretFile       string
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
	applyCmd.Flags().StringVar(&resourceURI, "resource-uri", "", "Resource URI in trustee (e.g., kbs:///default/kbsres1/key1)")
	applyCmd.Flags().StringVar(&secretFile, "secret-file", "", "Path inside container to mount the secret")
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
		return fmt.Errorf("failed to load config (run 'kubectl coco create-config' first): %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	// Determine runtime class to use
	rc := runtimeClass
	if rc == "" {
		if len(cfg.RuntimeClasses) > 0 {
			rc = cfg.RuntimeClasses[0] // Use first one as default
		} else {
			return fmt.Errorf("no runtime class specified and none found in config")
		}
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

	// 3. Handle sealed secrets if resource-uri is provided
	if resourceURI != "" {
		if err := handleSealedSecret(m, resourceURI); err != nil {
			return fmt.Errorf("failed to handle sealed secret: %w", err)
		}
	} else {
		// Auto-detect secrets and warn if found
		secrets := m.GetSecretRefs()
		if len(secrets) > 0 {
			fmt.Printf("  ⚠ Warning: Found %d secret reference(s) in manifest: %v\n", len(secrets), secrets)
			fmt.Println("    Secrets should be converted to sealed secrets for CoCo.")
			fmt.Println("    Use --resource-uri flag to create a sealed secret.")
		}
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
			image = "quay.io/fedora/fedora:44" // Default image
		}
	}

	// Determine the command to use
	var command []string
	if initContainerCmd != "" {
		// User provided custom command
		command = []string{"sh", "-c", initContainerCmd}
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

func handleSealedSecret(m *manifest.Manifest, resourceURI string) error {
	fmt.Printf("  - Converting secrets to sealed secrets (resource: %s)\n", resourceURI)

	// Get all secret references in the manifest
	secrets := m.GetSecretRefs()
	if len(secrets) == 0 {
		fmt.Println("    No secrets found in manifest, but will print sealed secret value")
	}

	// Generate sealed secret using coco-tools
	sealedValue, err := sealed.ConvertToSealed(resourceURI)
	if err != nil {
		return fmt.Errorf("failed to convert to sealed secret: %w", err)
	}

	fmt.Printf("    Generated sealed secret: %s\n", sealedValue)
	fmt.Println("    You need to create a Kubernetes secret with this value:")
	fmt.Printf("    kubectl create secret generic sealed-secret --from-literal=secret=%s\n", sealedValue)

	// Replace secret names in manifest if secrets exist
	if len(secrets) > 0 {
		for _, secretName := range secrets {
			fmt.Printf("    Replacing secret '%s' with 'sealed-secret'\n", secretName)
			if err := m.ReplaceSecretName(secretName, "sealed-secret"); err != nil {
				return fmt.Errorf("failed to replace secret name: %w", err)
			}
		}
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
