package cmd

import (
	"context"
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

	// Set context for Kubernetes client operations (required when auto-detecting RuntimeClass)
	cmd.SetContext(context.Background())

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

// TestInitCommand_CertDirWithEnableSidecar tests that --cert-dir is correctly applied
// together with --enable-sidecar, and that config has the expected certDir after validation.
// For each (enable-sidecar, cert-dir) combination we build config using the same logic as
// runInit (resolveCertDir), set required fields so Validate() passes, then assert certDir.
func TestInitCommand_CertDirWithEnableSidecar(t *testing.T) {
	defaultCertDir, err := config.GetDefaultCertDir()
	if err != nil {
		t.Fatalf("GetDefaultCertDir: %v", err)
	}
	customPath := "/custom/cert/path"

	tests := []struct {
		name          string
		enableSidecar bool
		certDir       string
		wantCertDir   string
	}{
		{"enable-sidecar=true, cert-dir empty -> default", true, "", defaultCertDir},
		{"enable-sidecar=true, cert-dir set -> path", true, customPath, customPath},
		{"enable-sidecar=false, cert-dir set -> path", false, customPath, customPath},
		{"enable-sidecar=false, cert-dir empty -> default", false, "", defaultCertDir},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Use same cert-dir resolution as runInit
			resolved, err := resolveCertDir(tt.certDir)
			if err != nil {
				t.Fatalf("resolveCertDir: %v", err)
			}
			cfg := config.DefaultConfig()
			cfg.Sidecar.CertDir = resolved
			cfg.Sidecar.Enabled = tt.enableSidecar
			// Set minimal fields so Validate() passes
			cfg.TrusteeServer = "https://trustee.example.com"
			cfg.RuntimeClass = "kata-cc"

			if err := cfg.Validate(); err != nil {
				t.Fatalf("config.Validate: %v", err)
			}

			if cfg.Sidecar.CertDir != tt.wantCertDir {
				t.Errorf("cfg.Sidecar.CertDir = %q, want %q", cfg.Sidecar.CertDir, tt.wantCertDir)
			}
		})
	}
}
