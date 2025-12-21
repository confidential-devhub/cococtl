package cmd

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/confidential-devhub/cococtl/pkg/cluster"
	"github.com/confidential-devhub/cococtl/pkg/config"
	"github.com/confidential-devhub/cococtl/pkg/sidecar/certs"
	"github.com/confidential-devhub/cococtl/pkg/trustee"
	"github.com/spf13/cobra"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize CoCo configuration and infrastructure",
	Long: `Initialize CoCo configuration file in ~/.kube/coco-config.toml

This command will:
  - Optionally deploy Trustee KBS to your cluster
  - Create configuration file with Trustee URL and other settings
  - Auto-detect RuntimeClass with SNP or TDX support (falls back to kata-cc)
  - Optionally set up sidecar certificates (with --enable-sidecar):
    - Generate Client CA and upload to Trustee KBS
    - Generate client certificate for developer access
    - Save client certificate to ~/.kube/coco-sidecar/
  - Prompt for configuration values including:
    - Trustee server URL (or auto-deploy)
    - Default RuntimeClass (auto-detected, can be overridden)
    - Trustee CA cert location (optional)
    - Kata-agent policy file path (optional)
    - Default init container image (optional)
    - Default init container command (optional)
    - PCCS URL for SGX attestation (optional)
    - Container policy URI (optional)
    - Container registry credentials URI (optional)
    - Container registry config URI (optional)`,
	RunE: runInit,
}

func init() {
	rootCmd.AddCommand(initCmd)
	initCmd.Flags().StringP("output", "o", "", "Output path for config file (default: ~/.kube/coco-config.toml)")
	initCmd.Flags().BoolP("interactive", "i", false, "Enable interactive prompts for configuration values")
	initCmd.Flags().Bool("skip-trustee-deploy", false, "Skip Trustee deployment")
	initCmd.Flags().String("trustee-namespace", "", "Namespace for Trustee deployment (default: current namespace)")
	initCmd.Flags().String("trustee-url", "", "Trustee server URL (skip deployment if provided)")
	initCmd.Flags().String("runtime-class", "", "RuntimeClass to use (default: kata-cc)")
	initCmd.Flags().Bool("enable-sidecar", false, "Enable sidecar and generate client CA and client certificates")
}

func runInit(cmd *cobra.Command, _ []string) error {
	outputPath, _ := cmd.Flags().GetString("output")
	interactive, _ := cmd.Flags().GetBool("interactive")
	skipTrusteeDeploy, _ := cmd.Flags().GetBool("skip-trustee-deploy")
	trusteeNamespace, _ := cmd.Flags().GetString("trustee-namespace")
	trusteeURL, _ := cmd.Flags().GetString("trustee-url")
	runtimeClass, _ := cmd.Flags().GetString("runtime-class")
	enableSidecar, _ := cmd.Flags().GetBool("enable-sidecar")

	// Get default config path if not specified
	if outputPath == "" {
		var err error
		outputPath, err = config.GetConfigPath()
		if err != nil {
			return fmt.Errorf("failed to get default config path: %w", err)
		}
	}

	// Check if config already exists
	if _, err := os.Stat(outputPath); err == nil {
		if interactive {
			fmt.Printf("Config file already exists at %s\n", outputPath)
			fmt.Print("Overwrite? (y/N): ")
			reader := bufio.NewReader(os.Stdin)
			response, _ := reader.ReadString('\n')
			response = strings.TrimSpace(strings.ToLower(response))
			if response != "y" && response != "yes" {
				fmt.Println("Aborted.")
				return nil
			}
		}
	}

	cfg := config.DefaultConfig()

	// Handle Trustee setup
	trusteeDeployed, actualNamespace, err := handleTrusteeSetup(cfg, interactive, skipTrusteeDeploy, trusteeNamespace, trusteeURL)
	if err != nil {
		return err
	}

	// Determine namespace for sidecar certificate upload
	// Use the actual namespace where Trustee was deployed
	sidecarNamespace := actualNamespace
	if sidecarNamespace == "" {
		// If Trustee wasn't deployed (user provided URL), use the flag value or default
		sidecarNamespace = trusteeNamespace
		if sidecarNamespace == "" {
			sidecarNamespace = "default"
		}
	}

	// Handle sidecar certificate setup if enabled
	if enableSidecar {
		if err := handleSidecarCertSetup(sidecarNamespace); err != nil {
			return err
		}
	}

	// Set runtime class from flag if provided, otherwise auto-detect
	if runtimeClass != "" {
		cfg.RuntimeClass = runtimeClass
	} else {
		// Auto-detect RuntimeClass with SNP or TDX support
		cfg.RuntimeClass = cluster.DetectRuntimeClass(config.DefaultRuntimeClass)
	}

	// In non-interactive mode, show the RuntimeClass being used
	if !interactive {
		fmt.Printf("RuntimeClass: %s\n", cfg.RuntimeClass)
	}

	// Continue with other configuration prompts if interactive
	if interactive {
		fmt.Println()
		cfg.RuntimeClass = promptString("Default RuntimeClass", cfg.RuntimeClass, false)
		// Only ask for CA cert if user provided their own Trustee URL
		if !trusteeDeployed {
			cfg.TrusteeCACert = promptString("Trustee CA cert location (optional)", cfg.TrusteeCACert, false)
		}
		cfg.KataAgentPolicy = promptString("Kata-agent policy file path (optional)", cfg.KataAgentPolicy, false)
		cfg.InitContainerImage = promptString("Default init container image (optional)", cfg.InitContainerImage, false)
		cfg.InitContainerCmd = promptString("Default init container command (optional)", cfg.InitContainerCmd, false)
		cfg.PCCSURL = promptString("PCCS URL for SGX attestation (optional)", cfg.PCCSURL, false)
		cfg.ContainerPolicyURI = promptString("Container policy URI (optional)", cfg.ContainerPolicyURI, false)
		cfg.RegistryCredURI = promptString("Container registry credentials URI (optional)", cfg.RegistryCredURI, false)
		cfg.RegistryConfigURI = promptString("Container registry config URI (optional)", cfg.RegistryConfigURI, false)
	}

	// Validate config
	if err := cfg.Validate(); err != nil {
		if !interactive && skipTrusteeDeploy && trusteeURL == "" {
			fmt.Printf("Warning: %v\n", err)
			fmt.Println("Config file created but needs to be edited before use")
		} else if !interactive {
			fmt.Printf("Warning: %v\n", err)
		} else {
			return fmt.Errorf("invalid configuration: %w", err)
		}
	}

	// Save config
	if err := cfg.Save(outputPath); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	fmt.Printf("\nConfiguration saved to: %s\n", outputPath)
	return nil
}

func promptString(prompt, defaultValue string, required bool) string {
	reader := bufio.NewReader(os.Stdin)

	requiredStr := ""
	if required {
		requiredStr = " (required)"
	}

	if defaultValue != "" {
		fmt.Printf("%s%s [%s]: ", prompt, requiredStr, defaultValue)
	} else {
		fmt.Printf("%s%s: ", prompt, requiredStr)
	}

	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	if input == "" {
		if required && defaultValue == "" {
			fmt.Println("This field is required. Please provide a value.")
			return promptString(prompt, defaultValue, required)
		}
		return defaultValue
	}

	return input
}

func handleTrusteeSetup(cfg *config.CocoConfig, interactive, skipDeploy bool, namespace, url string) (bool, string, error) {
	// If URL provided via flag, use it and skip deployment
	if url != "" {
		cfg.TrusteeServer = url
		if interactive {
			fmt.Printf("Using provided Trustee URL: %s\n", url)
		}
		return false, "", nil
	}

	// Interactive mode
	if interactive {
		fmt.Println("Initializing CoCo configuration...")
		fmt.Println()

		// Prompt for Trustee URL
		url := promptString("Trustee server URL (leave empty to deploy)", "", false)
		if url != "" {
			cfg.TrusteeServer = url
			return false, "", nil
		}

		// If empty, auto-deploy
		// Prompt for namespace if not provided
		if namespace == "" {
			namespace = promptString("Trustee namespace (press Enter for current)", "", false)
		}
	} else {
		// Non-interactive mode
		if skipDeploy {
			fmt.Println("Skipping Trustee deployment")
			fmt.Println("Warning: You must set trustee_server in the config file before use")
			return false, "", nil
		}

		fmt.Println("Deploying Trustee KBS...")
	}

	// Get current namespace if not specified
	if namespace == "" {
		var err error
		namespace, err = getCurrentNamespace()
		if err != nil {
			return false, "", err
		}
	}

	// Check if Trustee is already deployed
	deployed, err := trustee.IsDeployed(namespace)
	if err != nil {
		return false, "", fmt.Errorf("failed to check Trustee deployment: %w", err)
	}

	if deployed {
		fmt.Printf("Trustee already deployed in namespace '%s'\n", namespace)
		cfg.TrusteeServer = trustee.GetServiceURL(namespace, "trustee-kbs")
		return true, namespace, nil
	}

	// Deploy Trustee
	fmt.Printf("Deploying Trustee to namespace '%s'...\n", namespace)

	kbsImage := cfg.KBSImage
	if kbsImage == "" {
		kbsImage = config.DefaultKBSImage
	}

	trusteeCfg := &trustee.Config{
		Namespace:   namespace,
		ServiceName: "trustee-kbs",
		KBSImage:    kbsImage,
		PCCSURL:     cfg.PCCSURL,
	}

	if err := trustee.Deploy(trusteeCfg); err != nil {
		return false, "", fmt.Errorf("failed to deploy Trustee: %w", err)
	}

	cfg.TrusteeServer = trustee.GetServiceURL(namespace, "trustee-kbs")
	fmt.Printf("Trustee deployed successfully\n")
	fmt.Printf("Trustee URL: %s\n", cfg.TrusteeServer)

	return true, namespace, nil
}

// handleSidecarCertSetup generates and uploads sidecar certificates.
// It creates a Client CA, generates a client certificate for the developer,
// uploads the Client CA to Trustee KBS, and saves both the CA and client certificate locally.
// The CA is needed during 'apply' to sign per-app server certificates.
// The trusteeNamespace parameter specifies where the Trustee KBS pod is deployed.
func handleSidecarCertSetup(trusteeNamespace string) error {
	fmt.Println("\nSetting up sidecar certificates...")

	// Generate Client CA
	fmt.Println("  - Generating Client CA...")
	clientCA, err := certs.GenerateCA("CoCo Sidecar Client CA")
	if err != nil {
		return fmt.Errorf("failed to generate client CA: %w", err)
	}

	// Generate client certificate for developer
	fmt.Println("  - Generating client certificate...")
	clientCert, err := certs.GenerateClientCert(clientCA.CertPEM, clientCA.KeyPEM, "developer")
	if err != nil {
		return fmt.Errorf("failed to generate client certificate: %w", err)
	}

	// Upload Client CA to Trustee KBS
	// Note: We always use "default" namespace in the KBS path for consistency,
	// regardless of where Trustee is deployed. This ensures all apps reference
	// the same client CA location.
	const kbsResourceNamespace = "default"
	fmt.Printf("  - Uploading Client CA to Trustee KBS (Trustee namespace: %s, resource path: default)...\n", trusteeNamespace)
	clientCAPath := kbsResourceNamespace + "/sidecar-tls/client-ca"
	if err := trustee.UploadResource(trusteeNamespace, clientCAPath, clientCA.CertPEM); err != nil {
		return fmt.Errorf("failed to upload client CA to KBS: %w", err)
	}

	// Save certificates locally to ~/.kube/coco-sidecar/
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %w", err)
	}
	certDir := filepath.Join(homeDir, ".kube", "coco-sidecar")

	fmt.Printf("  - Saving certificates to %s...\n", certDir)

	// Save Client CA (needed to sign server certificates during apply)
	if err := clientCA.SaveToFile(certDir, "ca"); err != nil {
		return fmt.Errorf("failed to save client CA: %w", err)
	}

	// Save client certificate (for developer to access sidecars)
	if err := clientCert.SaveToFile(certDir, "client"); err != nil {
		return fmt.Errorf("failed to save client certificate: %w", err)
	}

	fmt.Println("\nSidecar certificates configured successfully!")
	fmt.Printf("  - Client CA uploaded to: kbs:///%s\n", clientCAPath)
	fmt.Printf("  - Client CA saved to: %s/ca-cert.pem (for signing server certs)\n", certDir)
	fmt.Printf("  - Client certificate saved to: %s/client-cert.pem\n", certDir)
	fmt.Printf("  - Client key saved to: %s/client-key.pem\n", certDir)

	return nil
}
