package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/confidential-devhub/cococtl/pkg/config"
	"github.com/confidential-devhub/cococtl/pkg/initdata"
	"github.com/confidential-devhub/cococtl/pkg/manifest"
	"github.com/confidential-devhub/cococtl/pkg/secrets"
	"github.com/confidential-devhub/cococtl/pkg/trustee"
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
	convertSecrets   bool
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
	applyCmd.Flags().BoolVar(&convertSecrets, "convert-secrets", true, "Automatically convert K8s secrets to sealed secrets")

	if err := applyCmd.MarkFlagRequired("filename"); err != nil {
		panic(fmt.Sprintf("failed to mark filename flag as required: %v", err))
	}
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
	if err := transformManifest(m, cfg, rc, skipApply); err != nil {
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

func transformManifest(m *manifest.Manifest, cfg *config.CocoConfig, rc string, skipApply bool) error {
	// 1. Set RuntimeClass
	fmt.Printf("  - Setting runtimeClassName: %s\n", rc)
	if err := m.SetRuntimeClass(rc); err != nil {
		return fmt.Errorf("failed to set runtime class: %w", err)
	}

	// 2. Convert secrets if enabled
	if convertSecrets {
		if err := handleSecrets(m, cfg, skipApply); err != nil {
			return fmt.Errorf("failed to convert secrets: %w", err)
		}
	} else {
		// Just warn about secrets
		secretRefs := m.GetSecretRefs()
		if len(secretRefs) > 0 {
			fmt.Printf("  ⚠ Warning: Found %d secret reference(s) in manifest: %v\n", len(secretRefs), secretRefs)
			fmt.Println("    Secrets should be converted to sealed secrets for CoCo.")
			fmt.Println("    Use --convert-secrets to enable automatic conversion.")
		}
	}

	// 3. Add initContainer if requested
	if addInitContainer {
		if err := handleInitContainer(m, cfg); err != nil {
			return fmt.Errorf("failed to add initContainer: %w", err)
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

func handleSecrets(m *manifest.Manifest, cfg *config.CocoConfig, skipApply bool) error {
	// 1. Detect all secret references
	secretRefs, err := secrets.DetectSecrets(m.GetData())
	if err != nil {
		return err
	}

	if len(secretRefs) == 0 {
		return nil // No secrets to convert
	}

	fmt.Printf("  - Found %d K8s secret(s) to convert\n", len(secretRefs))

	// 2. Inspect K8s secrets
	inspectedKeys, err := secrets.InspectSecrets(secretRefs)
	if err != nil {
		return fmt.Errorf("failed to inspect secrets via kubectl: %w\n\nTo fix:\n  1. Ensure kubectl is configured and can access the cluster\n  2. Create the secrets in the cluster first, then run this command\n  3. Or disable secret conversion with --convert-secrets=false", err)
	}

	// 3. Convert to sealed secrets
	sealedSecrets, err := secrets.ConvertSecrets(secretRefs, inspectedKeys)
	if err != nil {
		return err
	}

	fmt.Printf("  - Generated %d sealed secret(s)\n", len(sealedSecrets))

	// 4. Create or save sealed secrets based on skipApply flag
	var sealedSecretNames map[string]string
	if skipApply {
		// Generate YAML and save to file instead of creating in cluster
		fmt.Println("  - Generating sealed secret manifests")
		var yamlContent string
		sealedSecretNames, yamlContent, err = secrets.GenerateSealedSecretsYAML(sealedSecrets)
		if err != nil {
			return fmt.Errorf("failed to generate sealed secret YAML: %w", err)
		}

		// Save to file
		ext := filepath.Ext(m.GetName())
		if ext == "" {
			ext = ".yaml"
		}
		baseName := strings.TrimSuffix(manifestFile, ext)
		sealedSecretsPath := baseName + "-sealed-secrets.yaml"

		if err := os.WriteFile(sealedSecretsPath, []byte(yamlContent), 0644); err != nil {
			return fmt.Errorf("failed to write sealed secrets file: %w", err)
		}

		fmt.Printf("  - Sealed secrets saved to: %s\n", sealedSecretsPath)
	} else {
		// Create sealed secrets in cluster
		fmt.Println("  - Creating K8s sealed secrets in cluster")
		sealedSecretNames, err = secrets.CreateSealedSecrets(sealedSecrets)
		if err != nil {
			return fmt.Errorf("failed to create sealed secrets: %w", err)
		}
	}

	// 5. Update manifest to use sealed secret names
	fmt.Println("  - Updating manifest to use sealed secrets")
	if err := updateManifestSecretNames(m, sealedSecretNames); err != nil {
		return err
	}

	// 6. Add secrets to Trustee KBS repository (temporary solution)
	autoUploadSuccess := false
	trusteeNamespace, err := getTrusteeNamespace(cfg.TrusteeServer)
	if err != nil {
		fmt.Printf("  ⚠ Warning: Could not determine Trustee namespace from URL: %v\n", err)
		fmt.Println("    Skipping automatic secret upload to Trustee")
	} else {
		fmt.Println("  - Adding secrets to Trustee KBS repository")
		if err := addSecretsToTrustee(secretRefs, trusteeNamespace); err != nil {
			fmt.Printf("  ⚠ Warning: Failed to add secrets to Trustee: %v\n", err)
			fmt.Println("    You will need to add secrets manually")
		} else {
			fmt.Printf("  ✓ Successfully added %d secret(s) to Trustee\n", len(secretRefs))
			autoUploadSuccess = true
		}
	}

	// 7. Generate Trustee configuration
	ext := filepath.Ext(m.GetName())
	if ext == "" {
		ext = ".yaml"
	}
	baseName := strings.TrimSuffix(manifestFile, ext)
	trusteeConfigPath := baseName + "-trustee-secrets.json"

	if err := secrets.GenerateTrusteeConfig(sealedSecrets, trusteeConfigPath); err != nil {
		return fmt.Errorf("failed to generate Trustee config: %w", err)
	}

	// 8. Print instructions
	secrets.PrintTrusteeInstructions(sealedSecrets, trusteeConfigPath, autoUploadSuccess)

	return nil
}

// updateManifestSecretNames replaces all secret references with sealed secret names
func updateManifestSecretNames(m *manifest.Manifest, sealedSecretNames map[string]string) error {
	// Replace each original secret name with its sealed variant
	for originalName, sealedName := range sealedSecretNames {
		if err := m.ReplaceSecretName(originalName, sealedName); err != nil {
			return fmt.Errorf("failed to replace secret name %s: %w", originalName, err)
		}
		fmt.Printf("    %s → %s\n", originalName, sealedName)
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

// getTrusteeNamespace extracts the namespace from the Trustee server URL
// Expected format: http://trustee-kbs.{namespace}.svc.cluster.local:8080
func getTrusteeNamespace(trusteeURL string) (string, error) {
	if trusteeURL == "" {
		return "", fmt.Errorf("trustee server URL is empty")
	}

	// Remove protocol
	url := strings.TrimPrefix(trusteeURL, "http://")
	url = strings.TrimPrefix(url, "https://")

	// Remove port
	if idx := strings.Index(url, ":"); idx != -1 {
		url = url[:idx]
	}

	// Split by dots to get parts
	// Expected: trustee-kbs.{namespace}.svc.cluster.local
	parts := strings.Split(url, ".")
	if len(parts) < 2 {
		return "", fmt.Errorf("unexpected URL format: %s", trusteeURL)
	}

	// Check if it's a cluster-local service URL
	if len(parts) >= 3 && parts[2] == "svc" {
		// Second part is the namespace
		return parts[1], nil
	}

	// If not a cluster-local URL, we can't determine the namespace
	return "", fmt.Errorf("cannot determine namespace from non-cluster URL: %s", trusteeURL)
}

// addSecretsToTrustee adds all K8s secrets to the Trustee KBS repository
// This is a temporary solution until proper CLI tooling is available
func addSecretsToTrustee(secretRefs []secrets.SecretReference, trusteeNamespace string) error {
	// Import the trustee package function
	for _, ref := range secretRefs {
		// Determine the namespace for the secret
		// If the secret reference has a namespace, use it
		// Otherwise, use the current namespace
		secretNamespace := ref.Namespace
		if secretNamespace == "" {
			var err error
			secretNamespace, err = getCurrentNamespace()
			if err != nil {
				return fmt.Errorf("failed to get current namespace for secret %s: %w", ref.Name, err)
			}
		}

		// Add the secret to Trustee
		if err := addK8sSecretToTrustee(trusteeNamespace, ref.Name, secretNamespace); err != nil {
			return fmt.Errorf("failed to add secret %s: %w", ref.Name, err)
		}
	}

	return nil
}

// addK8sSecretToTrustee is a wrapper that calls the trustee package function
// This is kept separate to maintain the isolation of the temporary functionality
func addK8sSecretToTrustee(trusteeNamespace, secretName, secretNamespace string) error {
	return trustee.AddK8sSecretToTrustee(trusteeNamespace, secretName, secretNamespace)
}
