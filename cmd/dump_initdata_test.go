package cmd

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-devhub/cococtl/pkg/config"
	"github.com/confidential-devhub/cococtl/pkg/initdata"
)

// TestDumpInitdataWithValidConfig tests dump-initdata with a valid config file.
func TestDumpInitdataWithValidConfig(t *testing.T) {
	// Create temporary config file with valid TOML
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test-config.toml")

	validConfig := `trustee_server = "http://kbs-service.trustee-operator-system.svc.cluster.local:8080"
runtime_class = "kata-cc"
`

	if err := os.WriteFile(configPath, []byte(validConfig), 0600); err != nil {
		t.Fatalf("Failed to create test config: %v", err)
	}

	// Set the config path flag
	originalConfigPath := dumpInitdataConfigPath
	originalRaw := dumpInitdataRaw
	defer func() {
		dumpInitdataConfigPath = originalConfigPath
		dumpInitdataRaw = originalRaw
	}()

	dumpInitdataConfigPath = configPath
	dumpInitdataRaw = false

	// Capture stdout
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("Failed to create pipe: %v", err)
	}

	defer func() {
		_ = r.Close()
	}()

	os.Stdout = w

	runErr := runDumpInitdata(nil, nil)

	// Restore stdout and read captured output
	_ = w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	output := buf.String()

	if runErr != nil {
		t.Fatalf("runDumpInitdata failed: %v", runErr)
	}

	// Verify output contains expected section headers
	if !strings.Contains(output, "=== aa.toml ===") {
		t.Error("Output should contain '=== aa.toml ===' section header")
	}
	if !strings.Contains(output, "=== cdh.toml ===") {
		t.Error("Output should contain '=== cdh.toml ===' section header")
	}
	if !strings.Contains(output, "=== policy.rego ===") {
		t.Error("Output should contain '=== policy.rego ===' section header")
	}

	// Verify trustee server appears in the output
	if !strings.Contains(output, "kbs-service.trustee-operator-system.svc.cluster.local") {
		t.Error("Output should contain the configured trustee server URL")
	}
}

// TestDumpInitdataWithRawFlag tests dump-initdata with --raw flag.
func TestDumpInitdataWithRawFlag(t *testing.T) {
	// Create temporary config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test-config.toml")

	validConfig := `trustee_server = "http://kbs.test.svc:8080"
runtime_class = "kata-cc"
`

	if err := os.WriteFile(configPath, []byte(validConfig), 0600); err != nil {
		t.Fatalf("Failed to create test config: %v", err)
	}

	// Set the config path flag and enable raw mode
	originalConfigPath := dumpInitdataConfigPath
	originalRaw := dumpInitdataRaw
	defer func() {
		dumpInitdataConfigPath = originalConfigPath
		dumpInitdataRaw = originalRaw
	}()

	dumpInitdataConfigPath = configPath
	dumpInitdataRaw = true

	// Capture stdout
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("Failed to create pipe: %v", err)
	}

	defer func() {
		_ = r.Close()
	}()

	os.Stdout = w

	runErr := runDumpInitdata(nil, nil)

	// Restore stdout and read captured output
	_ = w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	output := buf.String()

	if runErr != nil {
		t.Fatalf("runDumpInitdata with --raw failed: %v", runErr)
	}

	// Find the base64 line (skip comment lines)
	lines := strings.Split(strings.TrimSpace(output), "\n")
	var base64Line string
	for _, line := range lines {
		if !strings.HasPrefix(line, "#") && len(line) > 0 {
			base64Line = line
			break
		}
	}

	if base64Line == "" {
		t.Fatal("Output should contain a base64-encoded string")
	}

	// Verify it's valid base64
	_, err = base64.StdEncoding.DecodeString(base64Line)
	if err != nil {
		t.Errorf("Output is not valid base64: %v", err)
	}

	// Verify comment header is present
	if !strings.Contains(output, "gzip+base64 encoded initdata") {
		t.Error("Output should contain explanatory comment about gzip+base64 encoding")
	}
}

// TestDumpInitdataMissingConfig tests dump-initdata with non-existent config file.
func TestDumpInitdataMissingConfig(t *testing.T) {
	// Set a non-existent config path
	originalConfigPath := dumpInitdataConfigPath
	originalRaw := dumpInitdataRaw
	defer func() {
		dumpInitdataConfigPath = originalConfigPath
		dumpInitdataRaw = originalRaw
	}()

	dumpInitdataConfigPath = "/nonexistent/path/to/config.toml"
	dumpInitdataRaw = false

	err := runDumpInitdata(nil, nil)

	if err == nil {
		t.Fatal("Expected error for missing config file, got nil")
	}

	// Verify error message mentions config loading failure
	if !strings.Contains(err.Error(), "failed to load config") {
		t.Errorf("Error message should mention 'failed to load config', got: %v", err)
	}
}

// TestDumpInitdataInvalidConfig tests dump-initdata with invalid TOML config.
func TestDumpInitdataInvalidConfig(t *testing.T) {
	// Create temporary file with invalid TOML
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "invalid-config.toml")

	invalidConfig := `trustee_server = "http://test.local
runtime_class = [broken
`

	if err := os.WriteFile(configPath, []byte(invalidConfig), 0600); err != nil {
		t.Fatalf("Failed to create test config: %v", err)
	}

	// Set the config path
	originalConfigPath := dumpInitdataConfigPath
	originalRaw := dumpInitdataRaw
	defer func() {
		dumpInitdataConfigPath = originalConfigPath
		dumpInitdataRaw = originalRaw
	}()

	dumpInitdataConfigPath = configPath
	dumpInitdataRaw = false

	err := runDumpInitdata(nil, nil)

	if err == nil {
		t.Fatal("Expected error for invalid TOML config, got nil")
	}

	// Verify error message indicates config or parsing failure
	if !strings.Contains(err.Error(), "failed to load config") && !strings.Contains(err.Error(), "parse") {
		t.Errorf("Error message should mention config loading or parsing failure, got: %v", err)
	}
}

// TestDecodeInitdata tests the decodeInitdata helper function.
func TestDecodeInitdata(t *testing.T) {
	// Create a simple test config
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test-config.toml")

	validConfig := `trustee_server = "http://test-kbs.default.svc:8080"
runtime_class = "kata-cc"
`

	if err := os.WriteFile(configPath, []byte(validConfig), 0600); err != nil {
		t.Fatalf("Failed to create test config: %v", err)
	}

	// Load config using the real config package
	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load test config: %v", err)
	}

	// Generate initdata using the real initdata package
	encoded, err := initdata.Generate(cfg, nil)
	if err != nil {
		t.Fatalf("Failed to generate initdata: %v", err)
	}

	// Now test decoding
	data, err := decodeInitdata(encoded)
	if err != nil {
		t.Fatalf("decodeInitdata failed: %v", err)
	}

	// Verify we got the expected keys
	if _, ok := data["aa.toml"]; !ok {
		t.Error("Decoded data should contain 'aa.toml' key")
	}
	if _, ok := data["cdh.toml"]; !ok {
		t.Error("Decoded data should contain 'cdh.toml' key")
	}
	if _, ok := data["policy.rego"]; !ok {
		t.Error("Decoded data should contain 'policy.rego' key")
	}

	// Verify aa.toml contains the trustee server URL
	if !strings.Contains(data["aa.toml"], "test-kbs.default.svc:8080") {
		t.Error("aa.toml should contain the configured trustee server URL")
	}
}
