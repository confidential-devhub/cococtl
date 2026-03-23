// Package initdata handles generation of initdata for Confidential Containers.
package initdata

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/confidential-devhub/cococtl/pkg/config"
	"github.com/pelletier/go-toml/v2"
)

// InitData constants define the version and algorithm for initdata generation
const (
	InitDataVersion   = "0.1.0"
	InitDataAlgorithm = "sha256"
)

// InitData represents the structure of initdata TOML.
// The [data] section holds the embedded configuration files keyed by filename.
type InitData struct {
	Algorithm string            `toml:"algorithm"`
	Version   string            `toml:"version"`
	Data      map[string]string `toml:"data"`
}

// ImagePullSecretInfo holds information about imagePullSecrets for initdata generation
type ImagePullSecretInfo struct {
	Namespace  string
	SecretName string
	Key        string
}

// Generate creates initdata based on the CoCo configuration
// imagePullSecrets is optional - pass nil if no imagePullSecrets need to be added
func Generate(cfg *config.CocoConfig, imagePullSecrets []ImagePullSecretInfo) (string, error) {
	if cfg.TrusteeServer == "" {
		return "", fmt.Errorf("trustee server URL is required for initdata generation")
	}

	// Read the CA cert once so that both aa.toml and cdh.toml are guaranteed
	// to embed identical content (avoids a TOCTOU window from multiple reads).
	var caCert string
	if cfg.TrusteeCACert != "" {
		raw, err := os.ReadFile(cfg.TrusteeCACert)
		if err != nil {
			return "", fmt.Errorf("failed to read CA cert from %q: %w", cfg.TrusteeCACert, err)
		}
		caCert = string(raw)
	}

	// Generate aa.toml (Attestation Agent configuration)
	aaToml, err := generateAAToml(cfg, caCert)
	if err != nil {
		return "", fmt.Errorf("failed to generate aa.toml: %w", err)
	}

	// Generate cdh.toml (Confidential Data Hub configuration)
	cdhToml, err := generateCDHToml(cfg, caCert, imagePullSecrets)
	if err != nil {
		return "", fmt.Errorf("failed to generate cdh.toml: %w", err)
	}

	// Get policy.rego
	var policy string
	if cfg.KataAgentPolicy != "" {
		policy, err = loadPolicyFile(cfg.KataAgentPolicy)
		if err != nil {
			return "", fmt.Errorf("failed to load policy file: %w", err)
		}
	} else {
		// Use default restrictive policy (exec disabled, logs enabled)
		policy = getDefaultPolicy()
	}

	id := InitData{
		Algorithm: InitDataAlgorithm,
		Version:   InitDataVersion,
		Data: map[string]string{
			"aa.toml":     aaToml,
			"cdh.toml":    cdhToml,
			"policy.rego": policy,
		},
	}

	tomlData, err := toml.Marshal(id)
	if err != nil {
		return "", fmt.Errorf("failed to marshal initdata: %w", err)
	}

	// Compress with gzip and encode to base64
	encoded, err := compressAndEncode(tomlData)
	if err != nil {
		return "", fmt.Errorf("failed to compress and encode initdata: %w", err)
	}

	return encoded, nil
}

// generateAAToml creates the Attestation Agent configuration.
// caCert is the PEM content of the CA certificate (empty string if not configured).
func generateAAToml(cfg *config.CocoConfig, caCert string) (string, error) {
	aaConfig := map[string]interface{}{
		"token_configs": map[string]interface{}{
			"kbs": map[string]interface{}{
				"url": cfg.TrusteeServer,
			},
		},
	}

	if caCert != "" {
		kbsConfig := aaConfig["token_configs"].(map[string]interface{})["kbs"].(map[string]interface{})
		kbsConfig["cert"] = caCert
	}

	tomlData, err := toml.Marshal(aaConfig)
	if err != nil {
		return "", fmt.Errorf("failed to marshal aa.toml: %w", err)
	}

	return string(tomlData), nil
}

// generateCDHToml creates the Confidential Data Hub configuration.
// caCert is the PEM content of the CA certificate (empty string if not configured).
func generateCDHToml(cfg *config.CocoConfig, caCert string, imagePullSecrets []ImagePullSecretInfo) (string, error) {
	cdhConfig := map[string]interface{}{
		"kbc": map[string]interface{}{
			"name": "cc_kbc",
			"url":  cfg.TrusteeServer,
		},
	}

	if caCert != "" {
		kbcConfig := cdhConfig["kbc"].(map[string]interface{})
		kbcConfig["kbs_cert"] = caCert
	}

	// Add image registry configuration if provided or if imagePullSecrets exist
	if cfg.RegistryConfigURI != "" || cfg.RegistryCredURI != "" || cfg.ContainerPolicyURI != "" || caCert != "" || len(imagePullSecrets) > 0 {
		imageConfig := make(map[string]interface{})

		// Add image security policy URI if provided
		if cfg.ContainerPolicyURI != "" {
			imageConfig["image_security_policy_uri"] = cfg.ContainerPolicyURI
		}

		// Add authenticated registry credentials URI
		// Priority: imagePullSecrets (dynamic) > config.RegistryCredURI (static)
		if len(imagePullSecrets) > 0 {
			// CDH spec only supports a single authenticated_registry_credentials_uri
			// Use the first (and typically only) imagePullSecret
			// Format: kbs:///namespace/secret-name/key
			ips := imagePullSecrets[0]
			uri := fmt.Sprintf("kbs:///%s/%s/%s", ips.Namespace, ips.SecretName, ips.Key)
			imageConfig["authenticated_registry_credentials_uri"] = uri
		} else if cfg.RegistryCredURI != "" {
			// Fall back to config value if no imagePullSecrets
			imageConfig["authenticated_registry_credentials_uri"] = cfg.RegistryCredURI
		}

		// Add registry configuration URI if provided
		if cfg.RegistryConfigURI != "" {
			imageConfig["registry_configuration_uri"] = cfg.RegistryConfigURI
		}

		if caCert != "" {
			imageConfig["extra_root_certificates"] = []string{caCert}
		}

		if len(imageConfig) > 0 {
			cdhConfig["image"] = imageConfig
		}
	}

	tomlData, err := toml.Marshal(cdhConfig)
	if err != nil {
		return "", fmt.Errorf("failed to marshal cdh.toml: %w", err)
	}

	return string(tomlData), nil
}

// loadPolicyFile reads a policy file from disk
func loadPolicyFile(path string) (string, error) {
	// Validate and sanitize the path to prevent directory traversal
	// Source - https://stackoverflow.com/a/57534618
	// Posted by Kenny Grant, modified by community. See post 'Timeline' for change history
	// Retrieved 2025-11-14, License - CC BY-SA 4.0
	cleanPath := filepath.Clean(path)

	// For absolute paths, validate they don't escape the filesystem root
	// For relative paths, ensure they're relative to current directory
	if filepath.IsAbs(cleanPath) {
		// Absolute paths are allowed for policy files
		// but ensure path doesn't contain traversal attempts
		if strings.Contains(path, "..") {
			return "", fmt.Errorf("invalid policy path: contains directory traversal")
		}
	} else {
		// For relative paths, ensure they resolve within current directory
		cwd, err := os.Getwd()
		if err != nil {
			return "", fmt.Errorf("failed to get current directory: %w", err)
		}
		absPath := filepath.Join(cwd, cleanPath)
		if !strings.HasPrefix(absPath, cwd) {
			return "", fmt.Errorf("invalid policy path: escapes current directory")
		}
		cleanPath = absPath
	}

	// #nosec G304 - Path is validated above
	data, err := os.ReadFile(cleanPath)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// getDefaultPolicy returns a default restrictive policy
func getDefaultPolicy() string {
	return `package agent_policy

default AddARPNeighborsRequest := true
default AddSwapRequest := true
default CloseStdinRequest := true
default CopyFileRequest := true
default CreateContainerRequest := true
default CreateSandboxRequest := true
default DestroySandboxRequest := true
default ExecProcessRequest := false
default GetMetricsRequest := true
default GetOOMEventRequest := true
default GuestDetailsRequest := true
default ListInterfacesRequest := true
default ListRoutesRequest := true
default MemHotplugByProbeRequest := true
default OnlineCPUMemRequest := true
default PauseContainerRequest := true
default PullImageRequest := true
default ReadStreamRequest := true
default RemoveContainerRequest := true
default RemoveStaleVirtiofsShareMountsRequest := true
default ReseedRandomDevRequest := true
default ResumeContainerRequest := true
default SetGuestDateTimeRequest := true
default SetPolicyRequest := false
default SignalProcessRequest := true
default StartContainerRequest := true
default StartTracingRequest := true
default StatsContainerRequest := true
default StopTracingRequest := true
default TtyWinResizeRequest := true
default UpdateContainerRequest := true
default UpdateEphemeralMountsRequest := true
default UpdateInterfaceRequest := true
default UpdateRoutesRequest := true
default WaitProcessRequest := true
default WriteStreamRequest := true
`
}

// compressAndEncode compresses data with gzip and encodes to base64
func compressAndEncode(data []byte) (string, error) {
	var buf bytes.Buffer

	gzipWriter := gzip.NewWriter(&buf)
	if _, err := gzipWriter.Write(data); err != nil {
		return "", fmt.Errorf("failed to compress data: %w", err)
	}

	if err := gzipWriter.Close(); err != nil {
		return "", fmt.Errorf("failed to close gzip writer: %w", err)
	}

	encoded := base64.StdEncoding.EncodeToString(buf.Bytes())
	return encoded, nil
}
