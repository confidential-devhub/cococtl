package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/confidential-devhub/cococtl/pkg/cluster"
	"github.com/confidential-devhub/cococtl/pkg/config"
	"github.com/confidential-devhub/cococtl/pkg/sidecar/certs"
	"github.com/spf13/cobra"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize CoCo configuration and infrastructure",
	Long: `Initialize CoCo configuration file in ~/.kube/coco-config.toml

This command will:
  - Create configuration file with Trustee URL and other settings
  - Auto-detect RuntimeClass with SNP or TDX support (falls back to kata-cc)
  - Optionally set up sidecar certificates (with --enable-sidecar):
    - Generate Client CA
    - Generate client certificate for developer access
    - Save all certificates and keys locally (default: ~/.kube/coco-sidecar, override with --cert-dir)
  - Prompt for configuration values including:
    - Trustee server URL (necessary only for initdata generation)
    - Default RuntimeClass (auto-detected, can be overridden)
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

	initCmd.Flags().String("trustee-url", "", "Trustee server URL (necessary only for initdata generation)")

	initCmd.Flags().String("runtime-class", "", "RuntimeClass to use (default: kata-cc)")

	initCmd.Flags().Bool("no-certs", false, "Do not generate sidecar certificates and keys (default: false)")
	initCmd.Flags().String("cert-dir", "", "Directory to store sidecar certificates and keys (default: ~/.kube/coco-sidecar)")
}

func runInit(cmd *cobra.Command, _ []string) error {
	outputPath, _ := cmd.Flags().GetString("output")
	interactive, _ := cmd.Flags().GetBool("interactive")
	trusteeURL, _ := cmd.Flags().GetString("trustee-url")
	runtimeClass, _ := cmd.Flags().GetString("runtime-class")
	noCerts, _ := cmd.Flags().GetBool("no-certs")
	certDir, _ := cmd.Flags().GetString("cert-dir")

	// Get default config path if not specified
	if outputPath == "" {
		var err error
		outputPath, err = config.GetConfigPath()
		if err != nil {
			return fmt.Errorf("failed to get default config path: %w", err)
		}
	}

	if noCerts == true && certDir != "" {
		return fmt.Errorf("cert-dir must not be specified when no-certs is true")
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

	if err := handleTrusteeSetup(cfg, interactive, trusteeURL); err != nil {
		return err
	}

	// Handle sidecar certificate setup
	if err := handleSidecarCertSetup(cfg, certDir, noCerts); err != nil {
		return err
	}

	fmt.Println()

	if err := handleRuntimeClassSetup(cfg, runtimeClass, interactive); err != nil {
		return err
	}

	// Continue with other configuration prompts if interactive
	if interactive {
		// Only ask for CA cert if user provided their own Trustee URL
		cfg.TrusteeCACert = promptString("Trustee CA cert location (optional)", cfg.TrusteeCACert, false)
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
		return fmt.Errorf("invalid configuration: %w", err)
	}

	// Save config
	if err := cfg.Save(outputPath); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}
	fmt.Printf("\nConfiguration saved to: %s\n", outputPath)

	if !interactive {
		fmt.Println("If you want to edit the config file to add more configuration, you can do so manually.")
	}

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

func handleTrusteeSetup(cfg *config.CocoConfig, interactive bool, trusteUrl string) error {

	if interactive {
		if trusteUrl != "" {
			fmt.Printf("Using provided Trustee URL: %s\n", trusteUrl)
			cfg.TrusteeServer = trusteUrl
		} else {
			trusteUrl = promptString("Trustee server URL", "", false)
			if trusteUrl != "" {
				cfg.TrusteeServer = trusteUrl
			}
		}

	} else {
		if trusteUrl != "" {
			cfg.TrusteeServer = trusteUrl
		}
	}

	return nil
}

// handleSidecarCertSetup generates and saves sidecar certificates.
func handleSidecarCertSetup(cfg *config.CocoConfig, certDir string, noCerts bool) error {

	if noCerts {
		cfg.Sidecar.NoCerts = true
		cfg.Sidecar.CertDir = ""
		fmt.Println("Skipping sidecar certificate generation (--no-certs is set)")
		return nil
	}
	cfg.Sidecar.NoCerts = false

	// Resolve cert directory for sidecar: use --cert-dir or default ~/.kube/coco-sidecar
	if certDir == "" {
		d, err := config.GetDefaultCertDir()
		if err != nil {
			return fmt.Errorf("failed to get default cert directory: %w", err)
		}
		certDir = d
	}
	cfg.Sidecar.CertDir = certDir

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

	fmt.Printf("  - Saving all certificates and keys to %s...\n", certDir)

	// Save Client CA (needed to sign server certificates during apply)
	if err := clientCA.SaveToFile(certDir, "ca"); err != nil {
		return fmt.Errorf("failed to save client CA: %w", err)
	}

	// Save client certificate (for developer to access sidecars)
	if err := clientCert.SaveToFile(certDir, "client"); err != nil {
		return fmt.Errorf("failed to save client certificate: %w", err)
	}

	fmt.Println("\nSidecar certificates configured successfully!")
	fmt.Println("  - All certificates and keys saved locally:")
	fmt.Printf("    - %s/ca-cert.pem, %s/ca-key.pem (Client CA for signing server certs)\n", certDir, certDir)
	fmt.Printf("    - %s/client-cert.pem,%s/ client-key.pem (client cert for developer access)\n", certDir, certDir)

	return nil
}

func handleRuntimeClassSetup(cfg *config.CocoConfig, runtimeClass string, interactive bool) error {
	// Set runtime class from flag if provided, otherwise auto-detect
	if runtimeClass != "" {
		cfg.RuntimeClass = runtimeClass
	} else {
		// Auto-detect RuntimeClass with SNP or TDX support
		cfg.RuntimeClass = cluster.DetectRuntimeClass(config.DefaultRuntimeClass)
	}

	if interactive {
		cfg.RuntimeClass = promptString(fmt.Sprintf("Default RuntimeClass (press Enter for %s)", config.DefaultRuntimeClass), cfg.RuntimeClass, false)
	} else {
		fmt.Printf("Using provided RuntimeClass: %s\n", cfg.RuntimeClass)
	}
	return nil
}
