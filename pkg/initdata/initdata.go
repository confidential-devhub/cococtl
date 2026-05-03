// Package initdata handles generation of initdata for Confidential Containers.
package initdata

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/confidential-devhub/cococtl/pkg/config"
	"github.com/pelletier/go-toml/v2"
)

// InitData constants define the version and algorithm for initdata generation
const (
	InitDataVersion   = "0.1.0"
	InitDataAlgorithm = "sha256"
)

// ValidAlgorithms lists all hash algorithms accepted during initdata validation.
var ValidAlgorithms = []string{"sha256", "sha384", "sha512"}

// IsValidAlgorithm reports whether alg is an accepted initdata algorithm.
func IsValidAlgorithm(alg string) bool {
	for _, v := range ValidAlgorithms {
		if alg == v {
			return true
		}
	}
	return false
}

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

// Generate creates initdata based on the CoCo configuration.
func Generate(cfg *config.CocoConfig, imagePullSecrets []ImagePullSecretInfo) (string, error) {
	raw, err := GenerateRaw(cfg, "", imagePullSecrets)
	if err != nil {
		return "", err
	}
	encoded, err := compressAndEncode(raw)
	if err != nil {
		return "", fmt.Errorf("failed to compress and encode initdata: %w", err)
	}
	return encoded, nil
}

// GenerateRaw returns the raw initdata TOML bytes without gzip/base64 encoding.
// When certPEM is non-empty it is used directly instead of reading cfg.TrusteeCACert.
func GenerateRaw(cfg *config.CocoConfig, certPEM string, imagePullSecrets []ImagePullSecretInfo) ([]byte, error) {
	if cfg.TrusteeServer == "" {
		return nil, fmt.Errorf("trustee server URL is required for initdata generation")
	}

	caCert := certPEM
	if caCert == "" && cfg.TrusteeCACert != "" {
		raw, err := os.ReadFile(cfg.TrusteeCACert)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA cert from %q: %w", cfg.TrusteeCACert, err)
		}
		caCert = string(raw)
	}

	aaToml, err := generateAAToml(cfg, caCert)
	if err != nil {
		return nil, fmt.Errorf("failed to generate aa.toml: %w", err)
	}

	cdhToml, err := generateCDHToml(cfg, caCert, imagePullSecrets)
	if err != nil {
		return nil, fmt.Errorf("failed to generate cdh.toml: %w", err)
	}

	var policy string
	if cfg.KataAgentPolicy != "" {
		policy, err = loadPolicyFile(cfg.KataAgentPolicy)
		if err != nil {
			return nil, fmt.Errorf("failed to load policy file: %w", err)
		}
	} else {
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

	return marshalInitData(id)
}

// marshalInitData serialises InitData to TOML using ''' literal multi-line strings
// for data values so the output is human-readable without escape sequences.
func marshalInitData(id InitData) ([]byte, error) {
	var sb strings.Builder
	fmt.Fprintf(&sb, "version = %q\n", id.Version)
	fmt.Fprintf(&sb, "algorithm = %q\n", id.Algorithm)
	sb.WriteString("\n[data]\n")

	keys := make([]string, 0, len(id.Data))
	for k := range id.Data {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		v := id.Data[k]
		if !strings.HasSuffix(v, "\n") {
			v += "\n"
		}
		fmt.Fprintf(&sb, "\n%q = '''\n%s'''\n", k, v)
	}
	return []byte(sb.String()), nil
}

// Decode decodes a base64+gzip encoded initdata string and returns the data map.
func Decode(encoded string) (map[string]string, error) {
	gzipData, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64: %w", err)
	}
	gzipReader, err := gzip.NewReader(bytes.NewReader(gzipData))
	if err != nil {
		return nil, fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer func() { _ = gzipReader.Close() }()
	tomlData, err := io.ReadAll(gzipReader)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress gzip data: %w", err)
	}
	var id InitData
	if err := toml.Unmarshal(tomlData, &id); err != nil {
		return nil, fmt.Errorf("failed to parse initdata TOML: %w", err)
	}
	return id.Data, nil
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
			// CDH spec only supports one URI; use the first entry.
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
	cleanPath := filepath.Clean(path)
	if !filepath.IsAbs(cleanPath) {
		cwd, err := os.Getwd()
		if err != nil {
			return "", fmt.Errorf("failed to get current directory: %w", err)
		}
		absPath := filepath.Join(cwd, cleanPath)
		rel, err := filepath.Rel(cwd, absPath)
		if err != nil || strings.HasPrefix(rel, "..") {
			return "", fmt.Errorf("policy path %q escapes working directory", path)
		}
		cleanPath = absPath
	}
	// #nosec G304 -- path is cleaned and validated; absolute paths are intentionally allowed
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
