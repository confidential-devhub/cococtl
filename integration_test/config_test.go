package integration_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/confidential-devhub/cococtl/pkg/config"
)

func TestConfig_Create_NonInteractiveWithDefaults(t *testing.T) {
	// Create temp directory for test
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")

	// Get default config
	cfg := config.DefaultConfig()
	cfg.TrusteeServer = "https://kbs.example.com" // Set required field

	// Save config
	err := cfg.Save(configPath)
	if err != nil {
		t.Fatalf("Failed to save config: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		t.Fatalf("Config file was not created at %s", configPath)
	}

	// Load and verify
	loaded, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Verify defaults are populated
	if loaded.RuntimeClass != config.DefaultRuntimeClass {
		t.Errorf("RuntimeClass = %q, want %q", loaded.RuntimeClass, config.DefaultRuntimeClass)
	}
	if loaded.InitContainerImage != config.DefaultInitContainerImage {
		t.Errorf("InitContainerImage = %q, want %q", loaded.InitContainerImage, config.DefaultInitContainerImage)
	}
	if loaded.InitContainerCmd != config.DefaultInitContainerCmd {
		t.Errorf("InitContainerCmd = %q, want %q", loaded.InitContainerCmd, config.DefaultInitContainerCmd)
	}
	if loaded.TrusteeServer != "https://kbs.example.com" {
		t.Errorf("TrusteeServer = %q, want %q", loaded.TrusteeServer, "https://kbs.example.com")
	}
}

func TestConfig_Create_CustomOutputPath(t *testing.T) {
	tmpDir := t.TempDir()
	customPath := filepath.Join(tmpDir, "custom", "my-config.toml")

	cfg := config.DefaultConfig()
	cfg.TrusteeServer = "https://kbs.example.com"

	// Save to custom path (should create directory)
	err := cfg.Save(customPath)
	if err != nil {
		t.Fatalf("Failed to save config to custom path: %v", err)
	}

	// Verify file exists at custom path
	if _, err := os.Stat(customPath); os.IsNotExist(err) {
		t.Fatalf("Config file was not created at custom path %s", customPath)
	}

	// Verify it's loadable
	loaded, err := config.Load(customPath)
	if err != nil {
		t.Fatalf("Failed to load config from custom path: %v", err)
	}

	if loaded.TrusteeServer != cfg.TrusteeServer {
		t.Errorf("Loaded config TrusteeServer = %q, want %q", loaded.TrusteeServer, cfg.TrusteeServer)
	}
}

func TestConfig_LoadAndValidate_ValidConfig(t *testing.T) {
	configPath := "testdata/configs/valid-config.toml"

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load valid config: %v", err)
	}

	// Verify fields parsed correctly
	if cfg.TrusteeServer != "https://kbs.example.com" {
		t.Errorf("TrusteeServer = %q, want %q", cfg.TrusteeServer, "https://kbs.example.com")
	}
	if cfg.RuntimeClass != "kata-cc" {
		t.Errorf("RuntimeClass = %q, want %q", cfg.RuntimeClass, "kata-cc")
	}

	// Verify validation passes
	err = cfg.Validate()
	if err != nil {
		t.Errorf("Valid config failed validation: %v", err)
	}
}

func TestConfig_LoadAndValidate_MissingTrusteeServer(t *testing.T) {
	configPath := "testdata/configs/invalid-no-trustee.toml"

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Verify validation fails
	err = cfg.Validate()
	if err == nil {
		t.Error("Expected validation error for missing trustee_server, got nil")
	}
}

func TestConfig_NormalizeURL_AddHTTPSPrefix(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "URL without protocol",
			input:    "kbs.example.com",
			expected: "https://kbs.example.com",
		},
		{
			name:     "URL with https",
			input:    "https://kbs.example.com",
			expected: "https://kbs.example.com",
		},
		{
			name:     "URL with http",
			input:    "http://kbs.example.com",
			expected: "http://kbs.example.com",
		},
		{
			name:     "URL with path",
			input:    "kbs.example.com/path",
			expected: "https://kbs.example.com/path",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.CocoConfig{
				TrusteeServer: tt.input,
				RuntimeClass:  "kata-cc",
			}

			cfg.NormalizeTrusteeServer()

			if cfg.TrusteeServer != tt.expected {
				t.Errorf("NormalizeTrusteeServer() = %q, want %q", cfg.TrusteeServer, tt.expected)
			}
		})
	}
}

func TestConfig_WithAnnotations(t *testing.T) {
	configPath := "testdata/configs/config-with-annotations.toml"

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config with annotations: %v", err)
	}

	// Verify annotations are loaded
	if cfg.Annotations == nil {
		t.Fatal("Annotations map is nil")
	}

	// Check specific annotations
	timeout := cfg.Annotations["io.katacontainers.config.runtime.create_container_timeout"]
	if timeout != "120" {
		t.Errorf("Timeout annotation = %q, want %q", timeout, "120")
	}

	machineType := cfg.Annotations["io.katacontainers.config.hypervisor.machine_type"]
	if machineType != "q35" {
		t.Errorf("Machine type annotation = %q, want %q", machineType, "q35")
	}
}

func TestConfig_GetConfigPath(t *testing.T) {
	path, err := config.GetConfigPath()
	if err != nil {
		t.Fatalf("GetConfigPath() failed: %v", err)
	}

	// Verify path contains expected components
	if !filepath.IsAbs(path) {
		t.Errorf("GetConfigPath() returned relative path: %s", path)
	}

	if filepath.Base(path) != "coco-config.toml" {
		t.Errorf("GetConfigPath() filename = %s, want coco-config.toml", filepath.Base(path))
	}

	// Verify path contains .kube directory
	if filepath.Base(filepath.Dir(path)) != ".kube" {
		t.Errorf("GetConfigPath() directory = %s, want .kube", filepath.Dir(path))
	}
}
