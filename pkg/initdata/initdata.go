package initdata

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"github.com/confidential-devhub/cococtl/pkg/config"
	"github.com/pelletier/go-toml/v2"
)

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

// Generate creates initdata based on the CoCo configuration
func Generate(cfg *config.CocoConfig) (string, error) {
	// Generate aa.toml (Attestation Agent configuration)
	aaToml, err := generateAAToml(cfg)
	if err != nil {
		return "", fmt.Errorf("failed to generate aa.toml: %w", err)
	}

	// Generate cdh.toml (Confidential Data Hub configuration)
	cdhToml, err := generateCDHToml(cfg)
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
		// Use default restrictive policy (exec and log disabled)
		policy = getDefaultPolicy()
	}

	// Manually construct TOML with multiline strings for proper formatting
	var tomlBuilder strings.Builder
	tomlBuilder.WriteString(fmt.Sprintf("version = '%s'\n", InitDataVersion))
	tomlBuilder.WriteString(fmt.Sprintf("algorithm = '%s'\n", InitDataAlgorithm))
	tomlBuilder.WriteString("'aa.toml' = '''\n")
	tomlBuilder.WriteString(aaToml)
	tomlBuilder.WriteString("'''\n")
	tomlBuilder.WriteString("'cdh.toml' = '''\n")
	tomlBuilder.WriteString(cdhToml)
	tomlBuilder.WriteString("'''\n\n")
	tomlBuilder.WriteString("[data]\n")
	tomlBuilder.WriteString("'policy.rego' = '''\n")
	tomlBuilder.WriteString(policy)
	tomlBuilder.WriteString("'''\n")

	tomlData := []byte(tomlBuilder.String())

	// Compress with gzip and encode to base64
	encoded, err := compressAndEncode(tomlData)
	if err != nil {
		return "", fmt.Errorf("failed to compress and encode initdata: %w", err)
	}

	return encoded, nil
}

// generateAAToml creates the Attestation Agent configuration
func generateAAToml(cfg *config.CocoConfig) (string, error) {
	aaConfig := map[string]interface{}{
		"token_configs": map[string]interface{}{
			"kbs": map[string]interface{}{
				"url": cfg.TrusteeServer,
			},
		},
	}

	// Add CA cert if provided
	if cfg.TrusteeCACert != "" {
		cert, err := os.ReadFile(cfg.TrusteeCACert)
		if err != nil {
			return "", fmt.Errorf("failed to read CA cert: %w", err)
		}
		kbsConfig := aaConfig["token_configs"].(map[string]interface{})["kbs"].(map[string]interface{})
		kbsConfig["cert"] = string(cert)
	}

	tomlData, err := toml.Marshal(aaConfig)
	if err != nil {
		return "", fmt.Errorf("failed to marshal aa.toml: %w", err)
	}

	return string(tomlData), nil
}

// generateCDHToml creates the Confidential Data Hub configuration
func generateCDHToml(cfg *config.CocoConfig) (string, error) {
	cdhConfig := map[string]interface{}{
		"kbc": map[string]interface{}{
			"name": "cc_kbc",
			"url":  cfg.TrusteeServer,
		},
	}

	// Add KBS cert if provided
	if cfg.TrusteeCACert != "" {
		cert, err := os.ReadFile(cfg.TrusteeCACert)
		if err != nil {
			return "", fmt.Errorf("failed to read CA cert: %w", err)
		}
		kbcConfig := cdhConfig["kbc"].(map[string]interface{})
		kbcConfig["kbs_cert"] = string(cert)
	}

	// Add image registry configuration if provided
	if cfg.RegistryConfigURI != "" || cfg.TrusteeCACert != "" {
		imageConfig := make(map[string]interface{})

		// If we have a custom CA cert, add it to extra_root_certificates
		if cfg.TrusteeCACert != "" {
			cert, err := os.ReadFile(cfg.TrusteeCACert)
			if err != nil {
				return "", fmt.Errorf("failed to read CA cert for image config: %w", err)
			}
			imageConfig["extra_root_certificates"] = []string{string(cert)}
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
	data, err := os.ReadFile(path)
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
default ReadStreamRequest := false
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
