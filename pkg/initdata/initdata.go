// Package initdata handles generation of initdata for Confidential Containers.
package initdata

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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

// InitData represents the structure of initdata TOML
type InitData struct {
	Version   string            `toml:"version"`
	Algorithm string            `toml:"algorithm"`
	AAToml    string            `toml:"aa.toml"`
	CDHToml   string            `toml:"cdh.toml"`
	Data      map[string]string `toml:"data"`
}

// ImagePullSecretInfo holds information about imagePullSecrets for initdata generation
type ImagePullSecretInfo struct {
	Namespace  string
	SecretName string
	Key        string
}

// buildInitdataTOML returns the raw initdata TOML bytes (before gzip+base64).
func buildInitdataTOML(cfg *config.CocoConfig, imagePullSecrets []ImagePullSecretInfo, trusteeURL string) ([]byte, error) {
	aaToml, err := generateAAToml(cfg, trusteeURL)
	if err != nil {
		return nil, fmt.Errorf("failed to generate aa.toml: %w", err)
	}
	cdhToml, err := generateCDHToml(cfg, imagePullSecrets)
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
	var tomlBuilder strings.Builder
	tomlBuilder.WriteString(fmt.Sprintf("algorithm = \"%s\"\n", InitDataAlgorithm))
	tomlBuilder.WriteString(fmt.Sprintf("version = \"%s\"\n", InitDataVersion))
	tomlBuilder.WriteString("\n[data]\n")
	tomlBuilder.WriteString("\"aa.toml\" = '''\n")
	tomlBuilder.WriteString(aaToml)
	tomlBuilder.WriteString("'''\n")
	tomlBuilder.WriteString("\"cdh.toml\" = '''\n")
	tomlBuilder.WriteString(cdhToml)
	tomlBuilder.WriteString("'''\n")
	tomlBuilder.WriteString("\"policy.rego\" = '''\n")
	tomlBuilder.WriteString(policy)
	tomlBuilder.WriteString("'''\n")
	return []byte(tomlBuilder.String()), nil
}

// Generate creates initdata based on the CoCo configuration
// imagePullSecrets is optional - pass nil if no imagePullSecrets need to be added
func Generate(cfg *config.CocoConfig, imagePullSecrets []ImagePullSecretInfo, trusteeURL string) (string, error) {
	if trusteeURL == "" {
		return "", fmt.Errorf("trustee server URL is required for initdata generation")
	}
	tomlData, err := buildInitdataTOML(cfg, imagePullSecrets, trusteeURL)
	if err != nil {
		return "", err
	}
	encoded, err := compressAndEncode(tomlData)
	if err != nil {
		return "", fmt.Errorf("failed to compress and encode initdata: %w", err)
	}
	return encoded, nil
}

// GenerateWithArtifacts returns the encoded initdata, the raw initdata TOML string (before gzip+base64),
// and the PCR8 reference value (SHA256(initial_pcr_32zeros || SHA256(toml))) used for attestation.
func GenerateWithArtifacts(cfg *config.CocoConfig, imagePullSecrets []ImagePullSecretInfo, trusteeURL string) (encoded string, rawTOML string, pcr8Hex string, err error) {
	if trusteeURL == "" {
		return "", "", "", fmt.Errorf("trustee server URL is required for initdata generation")
	}
	tomlData, err := buildInitdataTOML(cfg, imagePullSecrets, trusteeURL)
	if err != nil {
		return "", "", "", err
	}
	rawTOML = string(tomlData)
	encoded, err = compressAndEncode(tomlData)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to compress and encode initdata: %w", err)
	}
	// PCR8 = SHA256(initial_pcr_32_zero_bytes || SHA256(tomlData))
	hash := sha256.Sum256(tomlData)
	var pcr8Input [64]byte
	copy(pcr8Input[32:], hash[:])
	pcr8 := sha256.Sum256(pcr8Input[:])
	pcr8Hex = hex.EncodeToString(pcr8[:])
	return encoded, rawTOML, pcr8Hex, nil
}

// aaKBSConfig is used so the cert field is marshaled as TOML literal multi-line (”'...”').
// That keeps real newlines in the output instead of escaped \n.
type aaKBSConfig struct {
	URL  string `toml:"url"`
	Cert string `toml:"cert,omitempty,multiline"`
}

// generateAAToml creates the Attestation Agent configuration
func generateAAToml(cfg *config.CocoConfig, trusteeURL string) (string, error) {
	kbs := aaKBSConfig{URL: trusteeURL}
	if cfg.TrusteeCACert != "" {
		cert, err := os.ReadFile(cfg.TrusteeCACert)
		if err != nil {
			return "", fmt.Errorf("failed to read CA cert: %w", err)
		}
		kbs.Cert = string(cert)
	}
	aaConfig := map[string]interface{}{
		"token_configs": map[string]interface{}{
			"kbs": kbs,
		},
	}

	tomlData, err := toml.Marshal(aaConfig)
	if err != nil {
		return "", fmt.Errorf("failed to marshal aa.toml: %w", err)
	}

	return string(tomlData), nil
}

// cdhKBCConfig is used so kbs_cert is marshaled as TOML literal multi-line (”'...”').
// That keeps real newlines in the output instead of escaped \n.
type cdhKBCConfig struct {
	Name    string `toml:"name"`
	URL     string `toml:"url"`
	KbsCert string `toml:"kbs_cert,omitempty,multiline"`
}

// generateCDHToml creates the Confidential Data Hub configuration
func generateCDHToml(cfg *config.CocoConfig, imagePullSecrets []ImagePullSecretInfo) (string, error) {
	var trusteeCACertPEM string
	if cfg.TrusteeCACert != "" {
		cert, err := os.ReadFile(cfg.TrusteeCACert)
		if err != nil {
			return "", fmt.Errorf("failed to read CA cert: %w", err)
		}
		trusteeCACertPEM = string(cert)
	}

	kbc := cdhKBCConfig{Name: "cc_kbc", URL: cfg.TrusteeServer}
	if trusteeCACertPEM != "" {
		kbc.KbsCert = trusteeCACertPEM
	}
	cdhConfig := map[string]interface{}{
		"kbc": kbc,
	}

	// Add image registry configuration if provided or if imagePullSecrets exist
	if cfg.RegistryConfigURI != "" || cfg.RegistryCredURI != "" || cfg.ContainerPolicyURI != "" || cfg.TrusteeCACert != "" || len(imagePullSecrets) > 0 {
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

		// Add extra_root_certificates (placeholder for marshal; we rewrite to multiline below)
		if trusteeCACertPEM != "" {
			imageConfig["extra_root_certificates"] = []string{trusteeCACertPEM}
		}

		if len(imageConfig) > 0 {
			cdhConfig["image"] = imageConfig
		}
	}

	tomlData, err := toml.Marshal(cdhConfig)
	if err != nil {
		return "", fmt.Errorf("failed to marshal cdh.toml: %w", err)
	}

	tomlStr := string(tomlData)
	// Rewrite extra_root_certificates so each cert is TOML literal multi-line ("""..."""),
	// so newlines are preserved instead of escaped \n (CDH expects valid PEM).
	if trusteeCACertPEM != "" {
		tomlStr = replaceExtraRootCertificatesWithMultiline(tomlStr, trusteeCACertPEM)
	}

	return tomlStr, nil
}

// replaceExtraRootCertificatesWithMultiline finds the extra_root_certificates = ["..."]
// (or = ['...']) in the TOML and replaces it with literal multi-line form so newlines are preserved.
func replaceExtraRootCertificatesWithMultiline(tomlStr, certPEM string) string {
	idx := strings.Index(tomlStr, "extra_root_certificates")
	if idx == -1 {
		return tomlStr
	}
	// Skip to the opening bracket and then the opening quote (allow whitespace/newlines)
	searchStart := idx + len("extra_root_certificates")
	bracket := strings.Index(tomlStr[searchStart:], "[")
	if bracket == -1 {
		return tomlStr
	}
	afterBracket := searchStart + bracket + 1
	// Skip whitespace and newlines between [ and the quote
	for afterBracket < len(tomlStr) && (tomlStr[afterBracket] == ' ' || tomlStr[afterBracket] == '\t' || tomlStr[afterBracket] == '\n' || tomlStr[afterBracket] == '\r') {
		afterBracket++
	}
	if afterBracket >= len(tomlStr) {
		return tomlStr
	}
	quote := tomlStr[afterBracket]
	if quote != '"' && quote != '\'' {
		return tomlStr
	}
	start := afterBracket + 1 // first char of string content
	// Find closing quote (account for \" or \' and \\ inside)
	end := start
	for end < len(tomlStr) {
		if tomlStr[end] == '\\' && end+1 < len(tomlStr) {
			end += 2
			continue
		}
		if tomlStr[end] == quote {
			break
		}
		end++
	}
	if end >= len(tomlStr) || tomlStr[end] != quote {
		return tomlStr
	}
	// Find the closing "]" (may have whitespace/newline between quote and ])
	tail := end + 1
	for tail < len(tomlStr) && (tomlStr[tail] == ' ' || tomlStr[tail] == '\t' || tomlStr[tail] == '\n' || tomlStr[tail] == '\r') {
		tail++
	}
	if tail < len(tomlStr) && tomlStr[tail] == ']' {
		tail++ // skip ']' so rest of string starts after it
	} else {
		tail = end + 2 // fallback: assume "]"
	}
	// Replace with literal multi-line: extra_root_certificates = ["""\n<cert>\n"""]
	newVal := tomlStr[idx:searchStart] + ` = ["""
` + certPEM + `
"""]`
	return tomlStr[:idx] + newVal + tomlStr[tail:]
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
