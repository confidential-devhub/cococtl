// Package config provides configuration management for CoCo deployments.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

// Default configuration values.
const (
	DefaultRuntimeClass       = "kata-cc"
	DefaultInitContainerImage = "quay.io/fedora/fedora:44"
	DefaultInitContainerCmd   = "curl http://localhost:8006/cdh/resource/default/attestation-status/status"
	DefaultKBSImage           = "ghcr.io/confidential-containers/key-broker-service:built-in-as-v0.15.0"
	DefaultPCCSURL            = "https://api.trustedservices.intel.com/sgx/certification/v4/"
)

// CocoConfig represents the configuration for CoCo deployments.
type CocoConfig struct {
	TrusteeServer      string            `toml:"trustee_server" comment:"Trustee server URL (mandatory)"`
	RuntimeClass       string            `toml:"runtime_class" comment:"Default RuntimeClass to use when --runtime-class is not specified (default: kata-cc)"`
	TrusteeCACert      string            `toml:"trustee_ca_cert" comment:"Trustee CA cert location (optional)"`
	KataAgentPolicy    string            `toml:"kata_agent_policy" comment:"Kata-agent policy file path (optional)"`
	InitContainerImage string            `toml:"init_container_image" comment:"Default init container image (optional, default: quay.io/fedora/fedora:44)"`
	InitContainerCmd   string            `toml:"init_container_cmd" comment:"Default init container command (optional, default: attestation check)"`
	KBSImage           string            `toml:"kbs_image" comment:"KBS all-in-one image for Trustee deployment (optional, default: ghcr.io/confidential-containers/key-broker-service:built-in-as-v0.15.0)"`
	PCCSURL            string            `toml:"pccs_url" comment:"PCCS URL for SGX attestation (optional, default: https://api.trustedservices.intel.com/sgx/certification/v4/)"`
	ContainerPolicyURI string            `toml:"container_policy_uri" comment:"Container policy URI (optional)"`
	RegistryCredURI    string            `toml:"registry_cred_uri" comment:"Container registry credentials URI (optional)"`
	RegistryConfigURI  string            `toml:"registry_config_uri" comment:"Container registry config URI (optional)"`
	Annotations        map[string]string `toml:"annotations" comment:"Custom annotations to add to pods (optional)"`
}

// DefaultConfig returns a default CoCo configuration.
func DefaultConfig() *CocoConfig {
	return &CocoConfig{
		TrusteeServer:      "",
		RuntimeClass:       DefaultRuntimeClass,
		TrusteeCACert:      "",
		KataAgentPolicy:    "",
		InitContainerImage: DefaultInitContainerImage,
		InitContainerCmd:   DefaultInitContainerCmd,
		KBSImage:           DefaultKBSImage,
		PCCSURL:            DefaultPCCSURL,
		ContainerPolicyURI: "",
		RegistryCredURI:    "",
		RegistryConfigURI:  "",
		Annotations: map[string]string{
			"io.katacontainers.config.runtime.create_container_timeout": "",
			"io.katacontainers.config.hypervisor.machine_type":          "",
			"io.katacontainers.config.hypervisor.image":                 "",
		},
	}
}

// GetConfigPath returns the default config file path.
func GetConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get user home directory: %w", err)
	}
	return filepath.Join(home, ".kube", "coco-config.toml"), nil
}

// Load reads the configuration from the specified path.
func Load(path string) (*CocoConfig, error) {
	// Validate and sanitize the path to prevent directory traversal
	// Source - https://stackoverflow.com/a/57534618
	cleanPath := filepath.Clean(path)

	// For absolute paths, validate they don't escape the filesystem root
	// For relative paths, ensure they're relative to current directory
	if filepath.IsAbs(cleanPath) {
		// Absolute paths are allowed for config files (user may store anywhere)
		// but ensure path doesn't contain traversal attempts
		if strings.Contains(path, "..") {
			return nil, fmt.Errorf("invalid config path: contains directory traversal")
		}
	} else {
		// For relative paths, ensure they resolve within current directory
		cwd, err := os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("failed to get current directory: %w", err)
		}
		absPath := filepath.Join(cwd, cleanPath)
		if !strings.HasPrefix(absPath, cwd) {
			return nil, fmt.Errorf("invalid config path: escapes current directory")
		}
		cleanPath = absPath
	}

	// #nosec G304 - Path is validated above
	data, err := os.ReadFile(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg CocoConfig
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return &cfg, nil
}

// Save writes the configuration to the specified path.
func (c *CocoConfig) Save(path string) error {
	// Ensure the directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	data, err := toml.Marshal(c)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// Validate checks if the configuration is valid
func (c *CocoConfig) Validate() error {
	if c.TrusteeServer == "" {
		return fmt.Errorf("trustee_server is mandatory and cannot be empty")
	}
	if c.RuntimeClass == "" {
		return fmt.Errorf("runtime_class must be specified")
	}

	// Normalize trustee_server URL - add https:// prefix if no protocol is specified
	c.NormalizeTrusteeServer()

	return nil
}

// NormalizeTrusteeServer adds https:// prefix to trustee_server if no protocol is specified
func (c *CocoConfig) NormalizeTrusteeServer() {
	if c.TrusteeServer != "" && !strings.HasPrefix(c.TrusteeServer, "http://") && !strings.HasPrefix(c.TrusteeServer, "https://") {
		c.TrusteeServer = "https://" + c.TrusteeServer
	}
}
