package integration_test

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/confidential-devhub/cococtl/pkg/config"
	"github.com/confidential-devhub/cococtl/pkg/initdata"
	"github.com/pelletier/go-toml/v2"
)

func TestInitData_Generate_MinimalConfig(t *testing.T) {
	cfg, err := config.Load("testdata/configs/config-minimal.toml")
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	initdataValue, err := initdata.Generate(cfg)
	if err != nil {
		t.Fatalf("Generate() failed: %v", err)
	}

	// Verify base64 encoding
	if initdataValue == "" {
		t.Fatal("Generated initdata is empty")
	}

	// Decode and decompress
	decoded, err := base64.StdEncoding.DecodeString(initdataValue)
	if err != nil {
		t.Fatalf("Failed to decode base64: %v", err)
	}

	gzipReader, err := gzip.NewReader(bytes.NewReader(decoded))
	if err != nil {
		t.Fatalf("Failed to create gzip reader: %v", err)
	}
	defer func() {
		if err := gzipReader.Close(); err != nil {
			t.Errorf("Failed to close gzip reader: %v", err)
		}
	}()

	decompressed, err := io.ReadAll(gzipReader)
	if err != nil {
		t.Fatalf("Failed to decompress: %v", err)
	}

	// Parse TOML
	var data map[string]interface{}
	err = toml.Unmarshal(decompressed, &data)
	if err != nil {
		t.Fatalf("Failed to parse TOML: %v", err)
	}

	// Verify version and algorithm at top level
	if data["version"] != initdata.InitDataVersion {
		t.Errorf("version = %v, want %v", data["version"], initdata.InitDataVersion)
	}
	if data["algorithm"] != initdata.InitDataAlgorithm {
		t.Errorf("algorithm = %v, want %v", data["algorithm"], initdata.InitDataAlgorithm)
	}

	// Verify data section exists
	dataSection, ok := data["data"].(map[string]interface{})
	if !ok {
		t.Fatal("data section is missing or invalid")
	}

	// Verify aa.toml is present in data section
	aaToml, ok := dataSection["aa.toml"]
	if !ok || aaToml == "" {
		t.Error("aa.toml is missing or empty in data section")
	}

	// Verify cdh.toml is present in data section
	cdhToml, ok := dataSection["cdh.toml"]
	if !ok || cdhToml == "" {
		t.Error("cdh.toml is missing or empty in data section")
	}

	// Verify policy.rego in data section
	policyRego, ok := dataSection["policy.rego"]
	if !ok || policyRego == "" {
		t.Error("policy.rego is missing or empty in data section")
	}
}

func TestInitData_Generate_WithCACert(t *testing.T) {
	cfg, err := config.Load("testdata/configs/config-minimal.toml")
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Set CA cert path (relative to test execution, try both locations)
	cfg.TrusteeCACert = "testdata/certs/test-ca.crt"
	if _, err := os.Stat(cfg.TrusteeCACert); err != nil {
		cfg.TrusteeCACert = "integration_test/testdata/certs/test-ca.crt"
	}

	initdataValue, err := initdata.Generate(cfg)
	if err != nil {
		t.Fatalf("Generate() failed: %v", err)
	}

	// Decode and decompress
	decoded, err := base64.StdEncoding.DecodeString(initdataValue)
	if err != nil {
		t.Fatalf("Failed to decode base64: %v", err)
	}

	gzipReader, err := gzip.NewReader(bytes.NewReader(decoded))
	if err != nil {
		t.Fatalf("Failed to create gzip reader: %v", err)
	}
	defer func() {
		if err := gzipReader.Close(); err != nil {
			t.Errorf("Failed to close gzip reader: %v", err)
		}
	}()

	decompressed, err := io.ReadAll(gzipReader)
	if err != nil {
		t.Fatalf("Failed to decompress: %v", err)
	}

	// Verify CA cert content is present in the decompressed data
	if !strings.Contains(string(decompressed), "BEGIN CERTIFICATE") {
		t.Error("CA certificate content not found in initdata")
	}
}

func TestInitData_Generate_WithCustomPolicy(t *testing.T) {
	cfg, err := config.Load("testdata/configs/config-minimal.toml")
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Set policy path (relative to test execution)
	cfg.KataAgentPolicy = "testdata/policies/custom-policy.rego"

	// Check if file exists
	if _, err := os.Stat(cfg.KataAgentPolicy); err != nil {
		// Try with integration_test prefix
		cfg.KataAgentPolicy = "integration_test/testdata/policies/custom-policy.rego"
	}

	initdataValue, err := initdata.Generate(cfg)
	if err != nil {
		t.Fatalf("Generate() failed: %v", err)
	}

	// Decode and decompress
	decoded, err := base64.StdEncoding.DecodeString(initdataValue)
	if err != nil {
		t.Fatalf("Failed to decode base64: %v", err)
	}

	gzipReader, err := gzip.NewReader(bytes.NewReader(decoded))
	if err != nil {
		t.Fatalf("Failed to create gzip reader: %v", err)
	}
	defer func() {
		if err := gzipReader.Close(); err != nil {
			t.Errorf("Failed to close gzip reader: %v", err)
		}
	}()

	decompressed, err := io.ReadAll(gzipReader)
	if err != nil {
		t.Fatalf("Failed to decompress: %v", err)
	}

	// Parse TOML
	var data map[string]interface{}
	err = toml.Unmarshal(decompressed, &data)
	if err != nil {
		t.Fatalf("Failed to parse TOML: %v", err)
	}

	// Verify custom policy
	dataSection := data["data"].(map[string]interface{})
	policy := dataSection["policy.rego"].(string)

	// Custom policy allows exec
	if !strings.Contains(policy, "ExecProcessRequest := true") {
		t.Error("Custom policy not found (expected ExecProcessRequest := true)")
	}
}

func TestInitData_Generate_DefaultPolicy(t *testing.T) {
	cfg, err := config.Load("testdata/configs/config-minimal.toml")
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	initdataValue, err := initdata.Generate(cfg)
	if err != nil {
		t.Fatalf("Generate() failed: %v", err)
	}

	// Decode and decompress
	decoded, err := base64.StdEncoding.DecodeString(initdataValue)
	if err != nil {
		t.Fatalf("Failed to decode base64: %v", err)
	}

	gzipReader, err := gzip.NewReader(bytes.NewReader(decoded))
	if err != nil {
		t.Fatalf("Failed to create gzip reader: %v", err)
	}
	defer func() {
		if err := gzipReader.Close(); err != nil {
			t.Errorf("Failed to close gzip reader: %v", err)
		}
	}()

	decompressed, err := io.ReadAll(gzipReader)
	if err != nil {
		t.Fatalf("Failed to decompress: %v", err)
	}

	// Parse TOML
	var data map[string]interface{}
	err = toml.Unmarshal(decompressed, &data)
	if err != nil {
		t.Fatalf("Failed to parse TOML: %v", err)
	}

	// Verify default restrictive policy
	dataSection := data["data"].(map[string]interface{})
	policy := dataSection["policy.rego"].(string)

	// Default policy has exec disabled
	if !strings.Contains(policy, "ExecProcessRequest := false") {
		t.Error("Default policy not found (expected ExecProcessRequest := false)")
	}
	if !strings.Contains(policy, "ReadStreamRequest := false") {
		t.Error("Default policy should have ReadStreamRequest := false")
	}
}

func TestInitData_Encoding_GzipAndBase64(t *testing.T) {
	cfg, err := config.Load("testdata/configs/valid-config.toml")
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	initdataValue, err := initdata.Generate(cfg)
	if err != nil {
		t.Fatalf("Generate() failed: %v", err)
	}

	// Verify base64 encoding
	decoded, err := base64.StdEncoding.DecodeString(initdataValue)
	if err != nil {
		t.Fatalf("Failed to decode base64: %v", err)
	}

	// Verify gzip compression
	gzipReader, err := gzip.NewReader(bytes.NewReader(decoded))
	if err != nil {
		t.Fatalf("Failed to create gzip reader: %v", err)
	}
	defer func() {
		if err := gzipReader.Close(); err != nil {
			t.Errorf("Failed to close gzip reader: %v", err)
		}
	}()

	decompressed, err := io.ReadAll(gzipReader)
	if err != nil {
		t.Fatalf("Failed to decompress: %v", err)
	}

	// Verify TOML structure
	var data map[string]interface{}
	err = toml.Unmarshal(decompressed, &data)
	if err != nil {
		t.Fatalf("Failed to parse decompressed TOML: %v", err)
	}

	// Verify compression worked (compressed should be smaller)
	if len(decoded) >= len(decompressed) {
		t.Error("Gzip compression did not reduce size")
	}
}

func TestInitData_AAToml_Structure(t *testing.T) {
	cfg, err := config.Load("testdata/configs/valid-config.toml")
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	initdataValue, err := initdata.Generate(cfg)
	if err != nil {
		t.Fatalf("Generate() failed: %v", err)
	}

	// Decode and decompress
	decoded, err := base64.StdEncoding.DecodeString(initdataValue)
	if err != nil {
		t.Fatalf("Failed to decode base64: %v", err)
	}

	gzipReader, err := gzip.NewReader(bytes.NewReader(decoded))
	if err != nil {
		t.Fatalf("Failed to create gzip reader: %v", err)
	}
	defer func() {
		if err := gzipReader.Close(); err != nil {
			t.Errorf("Failed to close gzip reader: %v", err)
		}
	}()

	decompressed, err := io.ReadAll(gzipReader)
	if err != nil {
		t.Fatalf("Failed to decompress: %v", err)
	}

	// Parse TOML
	var data map[string]interface{}
	err = toml.Unmarshal(decompressed, &data)
	if err != nil {
		t.Fatalf("Failed to parse TOML: %v", err)
	}

	// Extract aa.toml from data section
	dataSection := data["data"].(map[string]interface{})
	aaToml := dataSection["aa.toml"].(string)

	// Parse aa.toml
	var aaData map[string]interface{}
	err = toml.Unmarshal([]byte(aaToml), &aaData)
	if err != nil {
		t.Fatalf("Failed to parse aa.toml: %v", err)
	}

	// Verify token_configs.kbs structure
	tokenConfigs, ok := aaData["token_configs"].(map[string]interface{})
	if !ok {
		t.Fatal("token_configs not found in aa.toml")
	}

	kbsConfig, ok := tokenConfigs["kbs"].(map[string]interface{})
	if !ok {
		t.Fatal("kbs config not found in token_configs")
	}

	// Verify URL
	if kbsConfig["url"] != cfg.TrusteeServer {
		t.Errorf("kbs url = %v, want %v", kbsConfig["url"], cfg.TrusteeServer)
	}
}

func TestInitData_CDHToml_Structure(t *testing.T) {
	cfg, err := config.Load("testdata/configs/valid-config.toml")
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	initdataValue, err := initdata.Generate(cfg)
	if err != nil {
		t.Fatalf("Generate() failed: %v", err)
	}

	// Decode and decompress
	decoded, err := base64.StdEncoding.DecodeString(initdataValue)
	if err != nil {
		t.Fatalf("Failed to decode base64: %v", err)
	}

	gzipReader, err := gzip.NewReader(bytes.NewReader(decoded))
	if err != nil {
		t.Fatalf("Failed to create gzip reader: %v", err)
	}
	defer func() {
		if err := gzipReader.Close(); err != nil {
			t.Errorf("Failed to close gzip reader: %v", err)
		}
	}()

	decompressed, err := io.ReadAll(gzipReader)
	if err != nil {
		t.Fatalf("Failed to decompress: %v", err)
	}

	// Parse TOML
	var data map[string]interface{}
	err = toml.Unmarshal(decompressed, &data)
	if err != nil {
		t.Fatalf("Failed to parse TOML: %v", err)
	}

	// Extract cdh.toml from data section
	dataSection := data["data"].(map[string]interface{})
	cdhToml := dataSection["cdh.toml"].(string)

	// Parse cdh.toml
	var cdhData map[string]interface{}
	err = toml.Unmarshal([]byte(cdhToml), &cdhData)
	if err != nil {
		t.Fatalf("Failed to parse cdh.toml: %v", err)
	}

	// Verify kbc structure
	kbcConfig, ok := cdhData["kbc"].(map[string]interface{})
	if !ok {
		t.Fatal("kbc config not found in cdh.toml")
	}

	// Verify kbc name and URL
	if kbcConfig["name"] != "cc_kbc" {
		t.Errorf("kbc name = %v, want cc_kbc", kbcConfig["name"])
	}
	if kbcConfig["url"] != cfg.TrusteeServer {
		t.Errorf("kbc url = %v, want %v", kbcConfig["url"], cfg.TrusteeServer)
	}
}
