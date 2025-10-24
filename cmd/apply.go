package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

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
	secretSpec       string
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
	applyCmd.Flags().StringVar(&secretSpec, "secret", "", "Secret specification (format: kbs://uri::path, e.g., kbs:///default/kbsres1/key1::/keys/key1)")
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

	// 3. Handle secrets if --secret is provided
	if secretSpec != "" {
		if err := handleSecret(m, secretSpec, cfg); err != nil {
			return fmt.Errorf("failed to handle secret: %w", err)
		}
	} else {
		// Auto-detect secrets and warn if found
		secrets := m.GetSecretRefs()
		if len(secrets) > 0 {
			fmt.Printf("  ⚠ Warning: Found %d secret reference(s) in manifest: %v\n", len(secrets), secrets)
			fmt.Println("    Secrets should be converted to sealed secrets for CoCo.")
			fmt.Println("    Use --secret flag to handle secrets (format: kbs://uri::path).")
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
			image = defaultInitContainerImage // Default image
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

func handleSecret(m *manifest.Manifest, secretSpec string, cfg *config.CocoConfig) error {
	// Parse secret specification: kbs://uri::path
	parts := strings.Split(secretSpec, "::")
	if len(parts) != 2 {
		return fmt.Errorf("invalid secret format, expected 'kbs://uri::path', got: %s", secretSpec)
	}

	resourceURI := parts[0]
	targetPath := parts[1]

	fmt.Printf("  - Handling secret (resource: %s, path: %s)\n", resourceURI, targetPath)

	// Convert kbs:// to CDH endpoint format
	// kbs:///default/kbsres1/key1 -> http://127.0.0.1:8006/cdh/resource/default/kbsres1/key1
	cdhURL := strings.Replace(resourceURI, "kbs://", "http://127.0.0.1:8006/cdh/resource", 1)

	// Extract volume name from target path (use parent directory name or "keys")
	volumeName := "keys"
	mountPath := strings.TrimSuffix(targetPath, "/"+getFileName(targetPath))
	if mountPath == "" {
		mountPath = "/keys"
	}

	// 1. Add emptyDir volume
	fmt.Printf("    Adding emptyDir volume '%s'\n", volumeName)
	emptyDirConfig := map[string]interface{}{
		"medium": "Memory",
	}
	if err := m.AddVolume(volumeName, "emptyDir", emptyDirConfig); err != nil {
		return fmt.Errorf("failed to add volume: %w", err)
	}

	// 2. Add initContainer to download secret
	fmt.Printf("    Adding secret download initContainer\n")
	initContainerCmd := fmt.Sprintf("curl -o %s %s", targetPath, cdhURL)
	command := []string{"sh", "-c", initContainerCmd}

	// Determine init container image
	image := defaultInitContainerImage
	if cfg.InitContainerImage != "" {
		image = cfg.InitContainerImage
	}

	// Create initContainer with volumeMount
	initContainer := map[string]interface{}{
		"name":    "get-key",
		"image":   image,
		"command": command,
		"volumeMounts": []interface{}{
			map[string]interface{}{
				"name":      volumeName,
				"mountPath": mountPath,
			},
		},
	}

	// Add initContainer manually (more control)
	spec, err := m.GetSpec()
	if err != nil {
		return fmt.Errorf("failed to get spec: %w", err)
	}

	var initContainers []interface{}
	if existing, ok := spec["initContainers"].([]interface{}); ok {
		initContainers = append([]interface{}{initContainer}, existing...)
	} else {
		initContainers = []interface{}{initContainer}
	}
	spec["initContainers"] = initContainers

	// 3. Add volumeMount to all containers
	fmt.Printf("    Adding volumeMount to containers (path: %s)\n", mountPath)
	if err := m.AddVolumeMountToContainer("", volumeName, mountPath); err != nil {
		return fmt.Errorf("failed to add volumeMount: %w", err)
	}

	return nil
}

// getFileName extracts the file name from a path
func getFileName(path string) string {
	parts := strings.Split(strings.TrimSuffix(path, "/"), "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return ""
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
