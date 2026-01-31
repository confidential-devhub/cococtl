package cmd

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/confidential-devhub/cococtl/pkg/cluster"
	"github.com/confidential-devhub/cococtl/pkg/config"
	"github.com/confidential-devhub/cococtl/pkg/initdata"
	"github.com/confidential-devhub/cococtl/pkg/manifest"
	"github.com/confidential-devhub/cococtl/pkg/secrets"
	"github.com/confidential-devhub/cococtl/pkg/sidecar"
	"github.com/confidential-devhub/cococtl/pkg/sidecar/certs"
	"github.com/confidential-devhub/cococtl/pkg/trustee"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

const (
	defaultInitContainerImage = "quay.io/fedora/fedora:44"
)

var applyCmd = &cobra.Command{
	Use:   "apply",
	Short: "Transform and apply a Kubernetes manifest for CoCo",
	Long: `Transform a regular Kubernetes manifest to a CoCo-enabled manifest and apply it.

This command will:
  1. Load the specified manifest (local file or URL)
  2. Add/update RuntimeClass
  3. Add initdata annotation (use --no-initdata to skip)
  4. Add first initContainer for attestation (if requested)
  5. Save a backup of the transformed manifest (*-coco.yaml)
  6. Apply the transformed manifest using kubectl

Supports both local files and remote URLs (http/https).

Example:
  kubectl coco apply -f app.yaml
  kubectl coco apply -f app.yaml --runtime-class kata-remote
  kubectl coco apply -f app.yaml --init-container
  kubectl coco apply -f https://raw.githubusercontent.com/user/repo/main/app.yaml`,
	RunE: runApply,
}

var (
	manifestFile        string
	runtimeClass        string
	addInitContainer    bool
	initContainerImg    string
	initContainerCmd    string
	skipApply           bool
	skipInitdata        bool
	configPath          string
	certDir             string
	convertSecrets      bool
	enableSidecar       bool
	sidecarImage        string
	sidecarSANIPs       string
	sidecarSANDNS       string
	sidecarSkipAutoSANs bool
	sidecarPortForward  int
)

func init() {
	rootCmd.AddCommand(applyCmd)

	applyCmd.Flags().StringVarP(&manifestFile, "filename", "f", "", "Path to Kubernetes manifest file or URL")
	applyCmd.Flags().StringVar(&runtimeClass, "runtime-class", "", "RuntimeClass to use (default from config)")
	applyCmd.Flags().BoolVar(&addInitContainer, "init-container", false, "Add default attestation initContainer")
	applyCmd.Flags().StringVar(&initContainerImg, "init-container-img", "", "Custom init container image (requires --init-container)")
	applyCmd.Flags().StringVar(&initContainerCmd, "init-container-cmd", "", "Custom init container command (requires --init-container)")
	applyCmd.Flags().BoolVar(&skipApply, "skip-apply", false, "Skip kubectl apply, only transform the manifest")
	applyCmd.Flags().BoolVar(&skipInitdata, "no-initdata", false, "Do not add the initdata annotation to the manifest")
	applyCmd.Flags().StringVar(&configPath, "config", "", "Path to CoCo config file (default: ~/.kube/coco-config.toml)")
	applyCmd.Flags().StringVar(&certDir, "cert-dir", "", "Directory containing sidecar Client CA and keys, for signing server certs (default: ~/.kube/coco-sidecar)")
	applyCmd.Flags().BoolVar(&convertSecrets, "convert-secrets", true, "Automatically convert K8s secrets to sealed secrets")
	applyCmd.Flags().BoolVar(&enableSidecar, "sidecar", false, "Enable secure access sidecar container")
	applyCmd.Flags().StringVar(&sidecarImage, "sidecar-image", "", "Custom sidecar image (requires --sidecar)")
	applyCmd.Flags().StringVar(&sidecarSANIPs, "sidecar-san-ips", "", "Comma-separated list of IP addresses for sidecar server certificate SANs")
	applyCmd.Flags().StringVar(&sidecarSANDNS, "sidecar-san-dns", "", "Comma-separated list of DNS names for sidecar server certificate SANs")
	applyCmd.Flags().BoolVar(&sidecarSkipAutoSANs, "sidecar-skip-auto-sans", false, "Skip auto-detection of SANs (node IPs and service DNS)")
	applyCmd.Flags().IntVar(&sidecarPortForward, "sidecar-port-forward", 0, "Port to forward from primary container (requires --sidecar)")
}

func runApply(_ *cobra.Command, _ []string) error {
	// Validate required flags (manual validation to keep all flags visible in shell completion)
	if manifestFile == "" {
		return fmt.Errorf("required flag(s) \"filename\" not set")
	}

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

	// Handle remote files
	actualManifestFile := manifestFile
	var tempFile string
	if isRemoteFile(manifestFile) {
		fmt.Printf("Downloading remote manifest: %s\n", manifestFile)
		var err error
		tempFile, err = downloadRemoteFile(manifestFile)
		if err != nil {
			return fmt.Errorf("failed to download remote manifest: %w", err)
		}
		defer func() {
			_ = os.Remove(tempFile)
		}()
		actualManifestFile = tempFile
		fmt.Printf("Downloaded to: %s\n", tempFile)
	}

	// Load manifest (supports multi-document YAML)
	fmt.Printf("Loading manifest: %s\n", actualManifestFile)
	manifestSet, err := manifest.LoadMultiDocument(actualManifestFile)
	if err != nil {
		return fmt.Errorf("failed to load manifest: %w", err)
	}

	// Get the primary workload manifest
	m := manifestSet.GetPrimaryManifest()
	if m == nil {
		return fmt.Errorf("no workload manifest (Pod, Deployment, etc.) found in file")
	}

	fmt.Printf("Transforming %s '%s' for CoCo...\n", m.GetKind(), m.GetName())

	// Validate initContainer flags
	if (initContainerImg != "" || initContainerCmd != "") && !addInitContainer {
		return fmt.Errorf("--init-container-img and --init-container-cmd require --init-container flag")
	}

	// Auto-detect sidecar port from Service if present and not manually specified
	if (enableSidecar || cfg.Sidecar.Enabled) && sidecarPortForward == 0 {
		detectedPort, err := manifestSet.GetServiceTargetPort()
		if err != nil {
			// Log warning but don't fail - user might provide port via config
			fmt.Printf("  ⚠ Warning: Could not auto-detect Service port: %v\n", err)
			fmt.Println("    You can manually specify --sidecar-port-forward")
		} else if detectedPort > 0 {
			// Validate port doesn't conflict with sidecar HTTPS port (8443)
			if detectedPort == 8443 {
				return fmt.Errorf("detected Service targetPort %d conflicts with sidecar HTTPS port 8443; please use a different port or specify --sidecar-port-forward manually", detectedPort)
			}
			sidecarPortForward = detectedPort
			fmt.Printf("  ✓ Auto-detected Service targetPort: %d (will be forwarded via sidecar)\n", sidecarPortForward)
		}
	}

	// Validate sidecar flags
	if sidecarPortForward > 0 && !enableSidecar && !cfg.Sidecar.Enabled {
		return fmt.Errorf("--sidecar-port-forward requires --sidecar flag or sidecar enabled in config")
	}

	// Additional validation: ensure forward port doesn't conflict with sidecar HTTPS port
	if sidecarPortForward == 8443 && (enableSidecar || cfg.Sidecar.Enabled) {
		return fmt.Errorf("sidecar port forward cannot be 8443 (conflicts with sidecar HTTPS port)")
	}

	// Resolve cert directory for sidecar: use --cert-dir or default ~/.kube/coco-sidecar
	if certDir == "" {
		d, err := config.GetDefaultCertDir()
		if err != nil {
			return fmt.Errorf("failed to get default cert directory: %w", err)
		}
		certDir = d
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

	// Generate and save Service manifest for sidecar if enabled
	var servicePath string
	if enableSidecar || cfg.Sidecar.Enabled {
		appName := m.GetName()
		namespace := m.GetNamespace()
		if namespace == "" {
			var err error
			namespace, err = getCurrentNamespace()
			if err != nil {
				return fmt.Errorf("failed to get current namespace: %w", err)
			}
		}

		fmt.Println("Generating Service manifest for sidecar...")
		serviceManifest, err := sidecar.GenerateService(m, cfg, appName, namespace)
		if err != nil {
			return fmt.Errorf("failed to generate sidecar Service: %w", err)
		}

		if len(serviceManifest) > 0 {
			// Save Service manifest with -sidecar-service suffix
			servicePath = strings.TrimSuffix(backupPath, ".yaml")
			servicePath = strings.TrimSuffix(servicePath, "-coco") + "-sidecar-service.yaml"

			serviceData, err := yaml.Marshal(serviceManifest)
			if err != nil {
				return fmt.Errorf("failed to marshal Service manifest: %w", err)
			}

			if err := os.WriteFile(servicePath, serviceData, 0600); err != nil {
				return fmt.Errorf("failed to write Service manifest: %w", err)
			}
			fmt.Printf("Sidecar Service manifest saved to: %s\n", servicePath)
		}
	}

	// Apply manifests if not skipped
	if !skipApply {
		fmt.Println("Applying manifest with kubectl...")
		if err := applyWithKubectl(backupPath); err != nil {
			return fmt.Errorf("failed to apply manifest: %w", err)
		}

		// Apply Service manifest if generated
		if servicePath != "" {
			fmt.Println("Applying sidecar Service manifest with kubectl...")
			if err := applyWithKubectl(servicePath); err != nil {
				return fmt.Errorf("failed to apply sidecar Service: %w", err)
			}
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

	// 3. Handle imagePullSecrets if present
	var imagePullSecretsInfo []initdata.ImagePullSecretInfo
	if convertSecrets {
		var err error
		imagePullSecretsInfo, err = handleImagePullSecrets(m, cfg, skipApply)
		if err != nil {
			return fmt.Errorf("failed to handle imagePullSecrets: %w", err)
		}
	}

	// 4. Add initContainer if requested
	if addInitContainer {
		if err := handleInitContainer(m, cfg); err != nil {
			return fmt.Errorf("failed to add initContainer: %w", err)
		}
	}

	// 5. Inject sidecar if enabled
	if enableSidecar || cfg.Sidecar.Enabled {
		// CLI flag overrides config
		if enableSidecar {
			cfg.Sidecar.Enabled = true
		}

		// CLI flag can override image
		if sidecarImage != "" {
			cfg.Sidecar.Image = sidecarImage
		}

		// CLI flag can override port forward
		if sidecarPortForward > 0 {
			cfg.Sidecar.ForwardPort = sidecarPortForward
		}

		// Extract app name and namespace for per-app certificate URIs
		appName := m.GetName()
		if appName == "" {
			return fmt.Errorf("manifest must have metadata.name for sidecar injection")
		}
		namespace := m.GetNamespace()
		if namespace == "" {
			// Use current kubectl namespace instead of hardcoding "default"
			var err error
			namespace, err = getCurrentNamespace()
			if err != nil {
				return fmt.Errorf("failed to get current namespace: %w", err)
			}
		}

		// Get Trustee namespace from config (where KBS is deployed; empty when trustee not configured)
		trusteeNamespace := cfg.GetTrusteeNamespace()

		// Load CA, build SANs, generate server cert; skip when no_certs is set in config (e.g. init --no-certs)
		if !cfg.Sidecar.NoCerts {
			fmt.Println("  - Setting up sidecar server certificate")
			if err := handleSidecarServerCert(appName, namespace, trusteeNamespace); err != nil {
				return fmt.Errorf("failed to setup sidecar server certificate: %w", err)
			}
		} else {
			fmt.Println("  - Skipping sidecar server certificate (no_certs is set in config)")
		}

		fmt.Println("  - Injecting secure access sidecar container")
		if err := sidecar.Inject(m, cfg, appName, "default"); err != nil {
			return fmt.Errorf("failed to inject sidecar: %w", err)
		}
	}

	// 6. Generate and add initdata annotation (skipped when --no-initdata)
	if !skipInitdata {
		fmt.Println("  - Generating initdata annotation")
		initdataValue, err := initdata.Generate(cfg, imagePullSecretsInfo)
		if err != nil {
			return fmt.Errorf("failed to generate initdata: %w", err)
		}

		if err := m.SetAnnotation("io.katacontainers.config.hypervisor.cc_init_data", initdataValue); err != nil {
			return fmt.Errorf("failed to set initdata annotation: %w", err)
		}
	} else {
		fmt.Println("  - Skipping initdata annotation (--no-initdata is set)")
	}

	// 7. Add custom annotations from config
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
	allSecretRefs, err := secrets.DetectSecrets(m.GetData())
	if err != nil {
		return err
	}

	// Filter out imagePullSecrets - they should NOT be converted to sealed secrets
	// They remain as regular K8s secrets and are only added to KBS via handleImagePullSecrets
	var secretRefs []secrets.SecretReference
	for _, ref := range allSecretRefs {
		isImagePullSecret := false
		for _, usage := range ref.Usages {
			if usage.Type == "imagePullSecrets" {
				isImagePullSecret = true
				break
			}
		}
		if !isImagePullSecret {
			secretRefs = append(secretRefs, ref)
		}
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

		if err := os.WriteFile(sealedSecretsPath, []byte(yamlContent), 0600); err != nil {
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

	// 6. Add secrets to Trustee KBS repository (only if not skipping apply)
	// FIXME: Use proper Trustee apis/CLI to add the secrets
	autoUploadSuccess := false
	if !skipApply {
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
	} else {
		fmt.Println("  - Skipping Trustee upload (--skip-apply mode)")
	}

	// 7. Generate Trustee configuration
	ext := filepath.Ext(m.GetName())
	if ext == "" {
		ext = ".yaml"
	}
	baseName := strings.TrimSuffix(manifestFile, ext)
	trusteeConfigPath := baseName + "-trustee-secrets.yaml"

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
	ctx := context.Background()
	cmd := exec.CommandContext(ctx, "kubectl", "apply", "-f", manifestPath)
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

		// Add the secret to Trustee (read from cluster/manifest namespace, store in KBS at "default")
		if err := addK8sSecretToTrustee(trusteeNamespace, ref.Name, secretNamespace, "default"); err != nil {
			return fmt.Errorf("failed to add secret %s: %w", ref.Name, err)
		}
	}

	return nil
}

// addK8sSecretToTrustee is a wrapper that calls the trustee package function.
// clusterNamespace: where to read the secret in the cluster; kbsPathNamespace: path in KBS (e.g. "default" for kbs:///default/secretName/key).
func addK8sSecretToTrustee(trusteeNamespace, secretName, clusterNamespace, kbsPathNamespace string) error {
	return trustee.AddK8sSecretToTrustee(trusteeNamespace, secretName, clusterNamespace, kbsPathNamespace)
}

// handleImagePullSecrets processes imagePullSecrets from the manifest
// It detects, uploads to KBS, and prepares them for initdata
// Falls back to default service account if no imagePullSecrets in manifest
func handleImagePullSecrets(m *manifest.Manifest, cfg *config.CocoConfig, skipApply bool) ([]initdata.ImagePullSecretInfo, error) {
	// Detect imagePullSecrets in manifest, with fallback to default service account
	imagePullSecretRefs, err := secrets.DetectImagePullSecretsWithServiceAccount(m.GetData())
	if err != nil {
		return nil, err
	}

	if len(imagePullSecretRefs) == 0 {
		return nil, nil // No imagePullSecrets to handle
	}

	fmt.Printf("  - Found %d imagePullSecret(s)\n", len(imagePullSecretRefs))

	// CDH only supports a single authenticated_registry_credentials_uri
	// If multiple imagePullSecrets are present, use only the first one
	if len(imagePullSecretRefs) > 1 {
		fmt.Printf("  ⚠ Warning: Multiple imagePullSecrets detected, but CDH supports only one\n")
		fmt.Printf("    Using only the first imagePullSecret: %s\n", imagePullSecretRefs[0].Name)
		imagePullSecretRefs = imagePullSecretRefs[:1]
	}

	// Inspect K8s secrets to get keys
	inspectedKeys, err := secrets.InspectSecrets(imagePullSecretRefs)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect imagePullSecrets via kubectl: %w\n\nTo fix:\n  1. Ensure kubectl is configured and can access the cluster\n  2. Create the imagePullSecrets in the cluster first, then run this command\n  3. Or disable secret conversion with --convert-secrets=false", err)
	}

	// Build ImagePullSecretInfo for initdata
	var imagePullSecretsInfo []initdata.ImagePullSecretInfo
	for _, ref := range imagePullSecretRefs {
		secretKeys, ok := inspectedKeys[ref.Name]
		if !ok {
			continue
		}

		// For each key in the imagePullSecret, create an entry
		for _, key := range secretKeys.Keys {
			// Use GetKBSKeyName to ensure consistent key name handling
			// This handles both .dockercfg -> .dockerconfigjson conversion
			// and stripping leading dots for KBS URI compatibility
			kbsKey := trustee.GetKBSKeyName(key)

			imagePullSecretsInfo = append(imagePullSecretsInfo, initdata.ImagePullSecretInfo{
				Namespace:  secretKeys.Namespace,
				SecretName: ref.Name,
				Key:        kbsKey,
			})
		}
	}

	// Upload imagePullSecrets to Trustee KBS (if not skipApply)
	if !skipApply {
		trusteeNamespace, err := getTrusteeNamespace(cfg.TrusteeServer)
		if err != nil {
			fmt.Printf("  ⚠ Warning: Could not determine Trustee namespace from URL: %v\n", err)
			fmt.Println("    Skipping automatic imagePullSecret upload to Trustee")
		} else {
			fmt.Println("  - Adding imagePullSecrets to Trustee KBS repository")
			if err := addImagePullSecretsToTrustee(imagePullSecretRefs, trusteeNamespace); err != nil {
				fmt.Printf("  ⚠ Warning: Failed to add imagePullSecrets to Trustee: %v\n", err)
				fmt.Println("    You will need to add imagePullSecrets manually")
			} else {
				fmt.Printf("  ✓ Successfully added %d imagePullSecret(s) to Trustee\n", len(imagePullSecretRefs))
			}
		}
	}

	// Note: We keep imagePullSecrets in the manifest as CRI-O still needs them for image pulls.
	// The authenticated_registry_credentials_uri in initdata is used by guest components.

	return imagePullSecretsInfo, nil
}

// addImagePullSecretsToTrustee adds all imagePullSecrets to the Trustee KBS repository
// This is a temporary solution until proper CLI tooling is available
func addImagePullSecretsToTrustee(secretRefs []secrets.SecretReference, trusteeNamespace string) error {
	for _, ref := range secretRefs {
		// Determine the namespace for the secret
		secretNamespace := ref.Namespace
		if secretNamespace == "" {
			var err error
			secretNamespace, err = getCurrentNamespace()
			if err != nil {
				return fmt.Errorf("failed to get current namespace for imagePullSecret %s: %w", ref.Name, err)
			}
		}

		// Add the imagePullSecret to Trustee
		if err := addImagePullSecretToTrustee(trusteeNamespace, ref.Name, secretNamespace); err != nil {
			return fmt.Errorf("failed to add imagePullSecret %s: %w", ref.Name, err)
		}
	}

	return nil
}

// addImagePullSecretToTrustee is a wrapper that calls the trustee package function
// This is kept separate to maintain the isolation of the temporary functionality
func addImagePullSecretToTrustee(trusteeNamespace, secretName, secretNamespace string) error {
	return trustee.AddImagePullSecretToTrustee(trusteeNamespace, secretName, secretNamespace)
}

// handleSidecarServerCert loads the Client CA, builds SANs, generates a server cert for the sidecar,
// and optionally uploads it to Trustee KBS. When trusteeNamespace is empty (e.g. trustee not configured),
// it still runs load/validate/generate for early feedback.
// Parameters:
//   - appName: name of the application (from manifest metadata.name)
//   - namespace: namespace for certificate KBS path (from manifest metadata.namespace)
//   - trusteeNamespace: namespace where Trustee KBS is deployed (used only when trusteeNamespace is not empty)
func handleSidecarServerCert(appName, namespace, trusteeNamespace string) error {
	caCertPath := filepath.Join(certDir, "ca-cert.pem")
	caKeyPath := filepath.Join(certDir, "ca-key.pem")

	// #nosec G304 -- Reading from known, trusted location in user's home directory
	caCert, err := os.ReadFile(caCertPath)
	if err != nil {
		return fmt.Errorf("failed to read client CA cert (run 'kubectl coco init --enable-sidecar' first): %w", err)
	}
	// #nosec G304 -- Reading from known, trusted location in user's home directory
	caKey, err := os.ReadFile(caKeyPath)
	if err != nil {
		return fmt.Errorf("failed to read client CA key: %w", err)
	}

	// Build SANs for server certificate
	sans := certs.SANs{
		DNSNames:    []string{},
		IPAddresses: []string{},
	}

	// Add user-provided SANs
	if sidecarSANIPs != "" {
		ipList := strings.Split(sidecarSANIPs, ",")
		for _, ip := range ipList {
			sans.IPAddresses = append(sans.IPAddresses, strings.TrimSpace(ip))
		}
	}
	if sidecarSANDNS != "" {
		dnsList := strings.Split(sidecarSANDNS, ",")
		for _, dns := range dnsList {
			sans.DNSNames = append(sans.DNSNames, strings.TrimSpace(dns))
		}
	}

	// Auto-detect SANs unless skipped
	if !sidecarSkipAutoSANs {
		// Auto-detect node IPs
		nodeIPs, err := cluster.GetNodeIPs()
		if err != nil {
			fmt.Printf("Warning: failed to auto-detect node IPs: %v\n", err)
		} else {
			sans.IPAddresses = append(sans.IPAddresses, nodeIPs...)
		}

		// Add service DNS names (format: <name>.<namespace>.svc.cluster.local)
		serviceDNS := fmt.Sprintf("%s.%s.svc.cluster.local", appName, namespace)
		sans.DNSNames = append(sans.DNSNames, serviceDNS)
	}

	if len(sans.DNSNames) == 0 && len(sans.IPAddresses) == 0 {
		return fmt.Errorf("no SANs configured for server certificate (use --sidecar-san-ips or --sidecar-san-dns, or enable auto-detection)")
	}

	fmt.Printf("  - Generating server certificate for %s with SANs:\n", appName)
	if len(sans.IPAddresses) > 0 {
		fmt.Printf("    IPs: %v\n", sans.IPAddresses)
	}
	if len(sans.DNSNames) > 0 {
		fmt.Printf("    DNS: %v\n", sans.DNSNames)
	}

	// Generate server certificate
	serverCert, err := certs.GenerateServerCert(caCert, caKey, appName, sans)
	if err != nil {
		return fmt.Errorf("failed to generate server certificate: %w", err)
	}

	// Save server certificate and key to certDir (always, for local use / backup)
	serverCertBaseName := fmt.Sprintf("server-%s-%s", appName, namespace)
	if err := serverCert.SaveToFile(certDir, serverCertBaseName); err != nil {
		return fmt.Errorf("failed to save server certificate to %s: %w", certDir, err)
	}
	fmt.Printf("  - Server certificate saved to %s/%s-cert.pem, %s-key.pem\n", certDir, serverCertBaseName, serverCertBaseName)

	if trusteeNamespace != "" {
		// Upload to Trustee KBS (in the namespace where Trustee is deployed)
		fmt.Printf("  - Uploading server certificate to Trustee KBS (namespace: %s)...\n", trusteeNamespace)
		serverCertPath := "default" + "/sidecar-tls-" + appName + "/server-cert"
		serverKeyPath := "default" + "/sidecar-tls-" + appName + "/server-key"

		resources := map[string][]byte{
			serverCertPath: serverCert.CertPEM,
			serverKeyPath:  serverCert.KeyPEM,
		}

		if err := trustee.UploadResources(trusteeNamespace, resources); err != nil {
			return fmt.Errorf("failed to upload server certificate to KBS: %w", err)
		}

		fmt.Printf("  - Server certificate uploaded to kbs:///%s and kbs:///%s\n", serverCertPath, serverKeyPath)
	} else {
		fmt.Println("  - Skipping server certificate upload to Trustee (trustee_server not configured)")
	}

	return nil
}
