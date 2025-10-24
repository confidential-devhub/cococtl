package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/pelletier/go-toml/v2"
)

// CocoConfig represents the configuration for CoCo deployments
type CocoConfig struct {
	TrusteeServer         string   `toml:"trustee_server" comment:"Trustee server URL (mandatory)"`
	RuntimeClasses        []string `toml:"runtime_classes" comment:"RuntimeClass to use (kata-cc and kata-remote as default)"`
	TrusteeCACert         string   `toml:"trustee_ca_cert" comment:"Trustee CA cert location (optional)"`
	KataAgentPolicy       string   `toml:"kata_agent_policy" comment:"Kata-agent policy file path (optional)"`
	InitContainerImage    string   `toml:"init_container_image" comment:"Init Container image for attestation (optional)"`
	ContainerPolicyURI    string   `toml:"container_policy_uri" comment:"Container policy URI (optional)"`
	RegistryCredURI       string   `toml:"registry_cred_uri" comment:"Container registry credentials URI (optional)"`
	RegistryConfigURI     string   `toml:"registry_config_uri" comment:"Container registry config URI (optional)"`
}

// DefaultConfig returns a default CoCo configuration
func DefaultConfig() *CocoConfig {
	return &CocoConfig{
		TrusteeServer:  "",
		RuntimeClasses: []string{"kata-cc", "kata-remote"},
		TrusteeCACert:  "",
		KataAgentPolicy: "",
		InitContainerImage: "",
		ContainerPolicyURI: "",
		RegistryCredURI: "",
		RegistryConfigURI: "",
	}
}

// GetConfigPath returns the default config file path
func GetConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get user home directory: %w", err)
	}
	return filepath.Join(home, ".kube", "coco-config.toml"), nil
}

// Load reads the configuration from the specified path
func Load(path string) (*CocoConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg CocoConfig
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return &cfg, nil
}

// Save writes the configuration to the specified path
func (c *CocoConfig) Save(path string) error {
	// Ensure the directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	data, err := toml.Marshal(c)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// Validate checks if the configuration is valid
func (c *CocoConfig) Validate() error {
	if c.TrusteeServer == "" {
		return fmt.Errorf("trustee_server is mandatory and cannot be empty")
	}
	if len(c.RuntimeClasses) == 0 {
		return fmt.Errorf("at least one runtime_class must be specified")
	}
	return nil
}
