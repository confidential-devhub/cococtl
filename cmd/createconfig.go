package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/confidential-devhub/cococtl/pkg/config"
	"github.com/spf13/cobra"
)

var createConfigCmd = &cobra.Command{
	Use:   "create-config",
	Short: "Create a CoCo configuration file",
	Long: `Create a CoCo configuration file in ~/.kube/coco-config.toml

This interactive command will prompt you for configuration values including:
  - Trustee server URL (mandatory)
  - Default RuntimeClass (default: kata-cc)
  - Trustee CA cert location (optional)
  - Kata-agent policy file path (optional)
  - Init Container image for attestation (optional)
  - Container policy URI (optional)
  - Container registry credentials URI (optional)
  - Container registry config URI (optional)`,
	RunE: runCreateConfig,
}

func init() {
	rootCmd.AddCommand(createConfigCmd)
	createConfigCmd.Flags().StringP("output", "o", "", "Output path for config file (default: ~/.kube/coco-config.toml)")
	createConfigCmd.Flags().Bool("non-interactive", false, "Use default values without prompting")
}

func runCreateConfig(cmd *cobra.Command, args []string) error {
	outputPath, _ := cmd.Flags().GetString("output")
	nonInteractive, _ := cmd.Flags().GetBool("non-interactive")

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

	if nonInteractive {
		fmt.Println("Creating config with default values...")
		fmt.Println("WARNING: You must edit the config file to set the mandatory trustee_server value")
	} else {
		fmt.Println("Creating CoCo configuration...")
		fmt.Println()

		// Prompt for configuration values
		cfg.TrusteeServer = promptString("Trustee server URL (mandatory)", cfg.TrusteeServer, true)
		cfg.RuntimeClass = promptString("Default RuntimeClass", cfg.RuntimeClass, false)
		cfg.TrusteeCACert = promptString("Trustee CA cert location (optional)", cfg.TrusteeCACert, false)
		cfg.KataAgentPolicy = promptString("Kata-agent policy file path (optional)", cfg.KataAgentPolicy, false)
		cfg.InitContainerImage = promptString("Init Container image (optional)", cfg.InitContainerImage, false)
		cfg.ContainerPolicyURI = promptString("Container policy URI (optional)", cfg.ContainerPolicyURI, false)
		cfg.RegistryCredURI = promptString("Container registry credentials URI (optional)", cfg.RegistryCredURI, false)
		cfg.RegistryConfigURI = promptString("Container registry config URI (optional)", cfg.RegistryConfigURI, false)
	}

	// Validate config
	if err := cfg.Validate(); err != nil {
		if nonInteractive {
			fmt.Printf("Warning: %v\n", err)
			fmt.Println("Config file created but needs to be edited before use")
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
