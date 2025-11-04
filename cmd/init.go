package cmd

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/confidential-devhub/cococtl/pkg/config"
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
  - Prompt for configuration values including:
    - Trustee server URL (or auto-deploy)
    - Default RuntimeClass (default: kata-cc)
    - Trustee CA cert location (optional)
    - Kata-agent policy file path (optional)
    - Default init container image (optional)
    - Default init container command (optional)
    - Container policy URI (optional)
    - Container registry credentials URI (optional)
    - Container registry config URI (optional)`,
	RunE: runInit,
}

func init() {
	rootCmd.AddCommand(initCmd)
	initCmd.Flags().StringP("output", "o", "", "Output path for config file (default: ~/.kube/coco-config.toml)")
	initCmd.Flags().Bool("non-interactive", false, "Use default values without prompting")
	initCmd.Flags().Bool("skip-trustee-deploy", false, "Skip Trustee deployment")
	initCmd.Flags().String("trustee-namespace", "", "Namespace for Trustee deployment (default: current namespace)")
	initCmd.Flags().String("trustee-url", "", "Trustee server URL (skip deployment if provided)")
}

func runInit(cmd *cobra.Command, args []string) error {
	outputPath, _ := cmd.Flags().GetString("output")
	nonInteractive, _ := cmd.Flags().GetBool("non-interactive")
	skipTrusteeDeploy, _ := cmd.Flags().GetBool("skip-trustee-deploy")
	trusteeNamespace, _ := cmd.Flags().GetString("trustee-namespace")
	trusteeURL, _ := cmd.Flags().GetString("trustee-url")

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
		if !nonInteractive {
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
	trusteeDeployed, err := handleTrusteeSetup(cfg, nonInteractive, skipTrusteeDeploy, trusteeNamespace, trusteeURL)
	if err != nil {
		return err
	}

	// Continue with other configuration prompts if interactive
	if !nonInteractive {
		fmt.Println()
		cfg.RuntimeClass = promptString("Default RuntimeClass", cfg.RuntimeClass, false)
		// Only ask for CA cert if user provided their own Trustee URL
		if !trusteeDeployed {
			cfg.TrusteeCACert = promptString("Trustee CA cert location (optional)", cfg.TrusteeCACert, false)
		}
		cfg.KataAgentPolicy = promptString("Kata-agent policy file path (optional)", cfg.KataAgentPolicy, false)
		cfg.InitContainerImage = promptString("Default init container image (optional)", cfg.InitContainerImage, false)
		cfg.InitContainerCmd = promptString("Default init container command (optional)", cfg.InitContainerCmd, false)
		cfg.ContainerPolicyURI = promptString("Container policy URI (optional)", cfg.ContainerPolicyURI, false)
		cfg.RegistryCredURI = promptString("Container registry credentials URI (optional)", cfg.RegistryCredURI, false)
		cfg.RegistryConfigURI = promptString("Container registry config URI (optional)", cfg.RegistryConfigURI, false)
	}

	// Validate config
	if err := cfg.Validate(); err != nil {
		if nonInteractive && skipTrusteeDeploy && trusteeURL == "" {
			fmt.Printf("Warning: %v\n", err)
			fmt.Println("Config file created but needs to be edited before use")
		} else if nonInteractive {
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

func getCurrentNamespace() (string, error) {
	cmd := exec.Command("kubectl", "config", "view", "--minify", "-o", "jsonpath={..namespace}")
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

func handleTrusteeSetup(cfg *config.CocoConfig, nonInteractive, skipDeploy bool, namespace, url string) (bool, error) {
	// If URL provided via flag, use it and skip deployment
	if url != "" {
		cfg.TrusteeServer = url
		if !nonInteractive {
			fmt.Printf("Using provided Trustee URL: %s\n", url)
		}
		return false, nil
	}

	// Interactive mode
	if !nonInteractive {
		fmt.Println("Initializing CoCo configuration...")
		fmt.Println()

		// Prompt for Trustee URL
		url := promptString("Trustee server URL (leave empty to deploy)", "", false)
		if url != "" {
			cfg.TrusteeServer = url
			return false, nil
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
			return false, nil
		}

		fmt.Println("Deploying Trustee KBS...")
	}

	// Get current namespace if not specified
	if namespace == "" {
		var err error
		namespace, err = getCurrentNamespace()
		if err != nil {
			return false, err
		}
	}

	// Check if Trustee is already deployed
	deployed, err := trustee.IsDeployed(namespace)
	if err != nil {
		return false, fmt.Errorf("failed to check Trustee deployment: %w", err)
	}

	if deployed {
		fmt.Printf("Trustee already deployed in namespace '%s'\n", namespace)
		cfg.TrusteeServer = trustee.GetServiceURL(namespace, "trustee-kbs")
		return true, nil
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
	}

	if err := trustee.Deploy(trusteeCfg); err != nil {
		return false, fmt.Errorf("failed to deploy Trustee: %w", err)
	}

	cfg.TrusteeServer = trustee.GetServiceURL(namespace, "trustee-kbs")
	fmt.Printf("Trustee deployed successfully\n")
	fmt.Printf("Trustee URL: %s\n", cfg.TrusteeServer)

	return true, nil
}
