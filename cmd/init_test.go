package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/confidential-devhub/cococtl/pkg/config"
)

// TestInitCommand_WithRuntimeClassFlag tests the init command with --runtime-class flag
func TestInitCommand_WithRuntimeClassFlag(t *testing.T) {
	// Create temp directory for test
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test-config.toml")

	// Create and execute init command with flags
	cmd := initCmd
	if err := cmd.Flags().Set("output", configPath); err != nil {
		t.Fatalf("Failed to set output flag: %v", err)
	}
	if err := cmd.Flags().Set("skip-trustee-deploy", "true"); err != nil {
		t.Fatalf("Failed to set skip-trustee-deploy flag: %v", err)
	}
	if err := cmd.Flags().Set("runtime-class", "kata-remote"); err != nil {
		t.Fatalf("Failed to set runtime-class flag: %v", err)
	}

	err := runInit(cmd, []string{})
	if err != nil {
		t.Fatalf("runInit failed: %v", err)
	}

	// Verify config file was created
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		t.Fatalf("Config file was not created at %s", configPath)
	}

	// Load and verify the config
	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Verify runtime class was set from flag
	if cfg.RuntimeClass != "kata-remote" {
		t.Errorf("RuntimeClass = %q, want %q", cfg.RuntimeClass, "kata-remote")
	}
}

// TestInitCommand_WithoutRuntimeClassFlag tests that default runtime class is used when flag is not provided
func TestInitCommand_WithoutRuntimeClassFlag(t *testing.T) {
	// Create temp directory for test
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test-config.toml")

	// Create and execute init command without runtime-class flag
	cmd := initCmd
	if err := cmd.Flags().Set("output", configPath); err != nil {
		t.Fatalf("Failed to set output flag: %v", err)
	}
	if err := cmd.Flags().Set("skip-trustee-deploy", "true"); err != nil {
		t.Fatalf("Failed to set skip-trustee-deploy flag: %v", err)
	}
	if err := cmd.Flags().Set("runtime-class", ""); err != nil { // Explicitly clear the flag
		t.Fatalf("Failed to set runtime-class flag: %v", err)
	}

	err := runInit(cmd, []string{})
	if err != nil {
		t.Fatalf("runInit failed: %v", err)
	}

	// Verify config file was created
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		t.Fatalf("Config file was not created at %s", configPath)
	}

	// Load and verify the config
	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Verify runtime class is set (either auto-detected or default)
	// Auto-detection may succeed or fail depending on cluster state,
	// but RuntimeClass should always be non-empty
	if cfg.RuntimeClass == "" {
		t.Errorf("RuntimeClass is empty, expected auto-detected or default value")
	}
	// Log what was detected for debugging
	t.Logf("RuntimeClass set to: %q", cfg.RuntimeClass)
}

// TestInitCommand_RuntimeClassWithTrusteeURL tests runtime-class flag with trustee-url
func TestInitCommand_RuntimeClassWithTrusteeURL(t *testing.T) {
	// Create temp directory for test
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test-config.toml")

	// Create and execute init command with both flags
	cmd := initCmd
	if err := cmd.Flags().Set("output", configPath); err != nil {
		t.Fatalf("Failed to set output flag: %v", err)
	}
	if err := cmd.Flags().Set("trustee-url", "https://trustee.example.com:8080"); err != nil {
		t.Fatalf("Failed to set trustee-url flag: %v", err)
	}
	if err := cmd.Flags().Set("runtime-class", "kata-qemu"); err != nil {
		t.Fatalf("Failed to set runtime-class flag: %v", err)
	}

	err := runInit(cmd, []string{})
	if err != nil {
		t.Fatalf("runInit failed: %v", err)
	}

	// Load and verify the config
	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Verify both values were set correctly
	if cfg.RuntimeClass != "kata-qemu" {
		t.Errorf("RuntimeClass = %q, want %q", cfg.RuntimeClass, "kata-qemu")
	}
	if cfg.TrusteeServer != "https://trustee.example.com:8080" {
		t.Errorf("TrusteeServer = %q, want %q", cfg.TrusteeServer, "https://trustee.example.com:8080")
	}
}
