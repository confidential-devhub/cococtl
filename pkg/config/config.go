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
	// Sidecar defaults
	DefaultSidecarImage       = "quay.io/confidential-devhub/coco-secure-access:latest"
	DefaultSidecarHTTPSPort   = 8443
	DefaultSidecarTLSCertURI  = "kbs:///default/sidecar-tls/server-cert"
	DefaultSidecarTLSKeyURI   = "kbs:///default/sidecar-tls/server-key"
	DefaultSidecarClientCAURI = "kbs:///default/sidecar-tls/client-ca"
	DefaultSidecarCPULimit    = "100m"
	DefaultSidecarMemLimit    = "128Mi"
	DefaultSidecarCPURequest  = "50m"
	DefaultSidecarMemRequest  = "64Mi"
)

// SidecarConfig represents the configuration for the secure access sidecar.
type SidecarConfig struct {
	Enabled       bool   `toml:"enabled" comment:"Enable secure access sidecar injection (default: false)"`
	Image         string `toml:"image" comment:"Sidecar container image (default: ghcr.io/confidential-containers/coco-secure-access:v0.1.0)"`
	HTTPSPort     int    `toml:"https_port" comment:"HTTPS server port (default: 8443)"`
	TLSCertURI    string `toml:"tls_cert_uri" comment:"Server TLS certificate KBS URI (required if sidecar enabled)"`
	TLSKeyURI     string `toml:"tls_key_uri" comment:"Server TLS key KBS URI (required if sidecar enabled)"`
	ClientCAURI   string `toml:"client_ca_uri" comment:"Client CA certificate KBS URI for mTLS (required if sidecar enabled)"`
	ForwardPort   int    `toml:"forward_port" comment:"Port to forward from primary container (optional)"`
	CPULimit      string `toml:"cpu_limit" comment:"CPU limit (default: 100m)"`
	MemoryLimit   string `toml:"memory_limit" comment:"Memory limit (default: 128Mi)"`
	CPURequest    string `toml:"cpu_request" comment:"CPU request (default: 50m)"`
	MemoryRequest string `toml:"memory_request" comment:"Memory request (default: 64Mi)"`
}

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
	Sidecar            SidecarConfig     `toml:"sidecar" comment:"Secure access sidecar configuration (optional)"`
}

// GetTrusteeNamespace extracts the namespace from the Trustee server URL.
// It parses URLs like "http://trustee-kbs.coco-test.svc.cluster.local:8080"
// and returns "coco-test". Returns "default" if parsing fails.
func (c *CocoConfig) GetTrusteeNamespace() string {
	url := c.TrusteeServer

	// Remove protocol if present
	url = strings.TrimPrefix(url, "http://")
	url = strings.TrimPrefix(url, "https://")

	// Remove port if present
	if idx := strings.Index(url, ":"); idx != -1 {
		url = url[:idx]
	}

	// Check for in-cluster service URL format: <service>.<namespace>.svc.cluster.local
	if strings.HasSuffix(url, ".svc.cluster.local") {
		parts := strings.Split(url, ".")
		if len(parts) >= 2 {
			return parts[1] // Return namespace
		}
	}

	// Check for simplified service URL format: <service>.<namespace>.svc
	if strings.HasSuffix(url, ".svc") {
		parts := strings.Split(url, ".")
		if len(parts) >= 2 {
			return parts[1] // Return namespace
		}
	}

	// Default to "default" namespace if we can't parse
	return "default"
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
		Sidecar: SidecarConfig{
			Enabled:       false,
			Image:         DefaultSidecarImage,
			HTTPSPort:     DefaultSidecarHTTPSPort,
			TLSCertURI:    DefaultSidecarTLSCertURI,
			TLSKeyURI:     DefaultSidecarTLSKeyURI,
			ClientCAURI:   DefaultSidecarClientCAURI,
			CPULimit:      DefaultSidecarCPULimit,
			MemoryLimit:   DefaultSidecarMemLimit,
			CPURequest:    DefaultSidecarCPURequest,
			MemoryRequest: DefaultSidecarMemRequest,
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

// GetDefaultCertDir returns the default directory for sidecar certificates and keys (~/.kube/coco-sidecar).
func GetDefaultCertDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get user home directory: %w", err)
	}
	return filepath.Join(home, ".kube", "coco-sidecar"), nil
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

	// Apply defaults for sidecar if not set
	applyDefaults(&cfg)

	return &cfg, nil
}

// applyDefaults applies default values to config fields if they are not set.
func applyDefaults(cfg *CocoConfig) {
	// Apply sidecar defaults
	if cfg.Sidecar.Image == "" {
		cfg.Sidecar.Image = DefaultSidecarImage
	}
	if cfg.Sidecar.HTTPSPort == 0 {
		cfg.Sidecar.HTTPSPort = DefaultSidecarHTTPSPort
	}
	if cfg.Sidecar.TLSCertURI == "" {
		cfg.Sidecar.TLSCertURI = DefaultSidecarTLSCertURI
	}
	if cfg.Sidecar.TLSKeyURI == "" {
		cfg.Sidecar.TLSKeyURI = DefaultSidecarTLSKeyURI
	}
	if cfg.Sidecar.ClientCAURI == "" {
		cfg.Sidecar.ClientCAURI = DefaultSidecarClientCAURI
	}
	if cfg.Sidecar.CPULimit == "" {
		cfg.Sidecar.CPULimit = DefaultSidecarCPULimit
	}
	if cfg.Sidecar.MemoryLimit == "" {
		cfg.Sidecar.MemoryLimit = DefaultSidecarMemLimit
	}
	if cfg.Sidecar.CPURequest == "" {
		cfg.Sidecar.CPURequest = DefaultSidecarCPURequest
	}
	if cfg.Sidecar.MemoryRequest == "" {
		cfg.Sidecar.MemoryRequest = DefaultSidecarMemRequest
	}
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
