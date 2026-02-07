package secrets

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestGenerateTrusteeConfig(t *testing.T) {
	sealedSecrets := []*SealedSecretData{
		{
			ResourceURI:  "kbs:///default/db-creds/password",
			SealedSecret: "sealed.fakejwsheader.eyJ2ZXJzaW9uIjoiMC4xLjAiLCJ0eXBlIjoidmF1bHQiLCJuYW1lIjoia2JzOi8vL2RlZmF1bHQvZGItY3JlZHMvcGFzc3dvcmQiLCJwcm92aWRlciI6ImticyIsInByb3ZpZGVyX3NldHRpbmdzIjp7fSwiYW5ub3RhdGlvbnMiOnt9fQ.fakesignature",
			SecretName:   "db-creds",
			Key:          "password",
			Namespace:    "default",
		},
	}

	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "trustee-config.json")

	err := GenerateTrusteeConfig(sealedSecrets, outputPath)
	if err != nil {
		t.Fatalf("GenerateTrusteeConfig() failed: %v", err)
	}

	// Verify file was created
	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		t.Fatal("Trustee config file was not created")
	}

	// Read and parse the file
	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("Failed to read output file: %v", err)
	}

	var config TrusteeConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		t.Fatalf("Failed to parse YAML: %v", err)
	}

	// Verify content
	if len(config.Secrets) != 1 {
		t.Fatalf("Expected 1 secret in config, got %d", len(config.Secrets))
	}

	entry := config.Secrets[0]
	if entry.ResourceURI != "kbs:///default/db-creds/password" {
		t.Errorf("ResourceURI = %q, want %q", entry.ResourceURI, "kbs:///default/db-creds/password")
	}

	if entry.SealedSecret == "" {
		t.Error("SealedSecret is empty")
	}

	// Verify JSON spec is present and valid
	if entry.JSON == nil {
		t.Fatal("JSON spec is nil")
	}

	if entry.JSON["version"] != "0.1.0" {
		t.Errorf("JSON version = %v, want %q", entry.JSON["version"], "0.1.0")
	}

	if entry.JSON["provider"] != "kbs" {
		t.Errorf("JSON provider = %v, want %q", entry.JSON["provider"], "kbs")
	}

	if entry.JSON["name"] != "kbs:///default/db-creds/password" {
		t.Errorf("JSON name = %v, want %q", entry.JSON["name"], "kbs:///default/db-creds/password")
	}
}

func TestGenerateTrusteeConfig_MultipleSecrets(t *testing.T) {
	sealedSecrets := []*SealedSecretData{
		{
			ResourceURI:  "kbs:///default/db-creds/password",
			SealedSecret: "sealed.fakejwsheader.eyJ2ZXJzaW9uIjoiMC4xLjAiLCJ0eXBlIjoidmF1bHQiLCJuYW1lIjoia2JzOi8vL2RlZmF1bHQvZGItY3JlZHMvcGFzc3dvcmQiLCJwcm92aWRlciI6ImticyIsInByb3ZpZGVyX3NldHRpbmdzIjp7fSwiYW5ub3RhdGlvbnMiOnt9fQ.fakesignature",
			SecretName:   "db-creds",
			Key:          "password",
			Namespace:    "default",
		},
		{
			ResourceURI:  "kbs:///default/api-secret/key",
			SealedSecret: "sealed.fakejwsheader.eyJ2ZXJzaW9uIjoiMC4xLjAiLCJ0eXBlIjoidmF1bHQiLCJuYW1lIjoia2JzOi8vL2RlZmF1bHQvYXBpLXNlY3JldC9rZXkiLCJwcm92aWRlciI6ImticyIsInByb3ZpZGVyX3NldHRpbmdzIjp7fSwiYW5ub3RhdGlvbnMiOnt9fQ.fakesignature",
			SecretName:   "api-secret",
			Key:          "key",
			Namespace:    "default",
		},
	}

	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "trustee-config.json")

	err := GenerateTrusteeConfig(sealedSecrets, outputPath)
	if err != nil {
		t.Fatalf("GenerateTrusteeConfig() failed: %v", err)
	}

	// Read and parse the file
	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("Failed to read output file: %v", err)
	}

	var config TrusteeConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		t.Fatalf("Failed to parse YAML: %v", err)
	}

	if len(config.Secrets) != 2 {
		t.Fatalf("Expected 2 secrets in config, got %d", len(config.Secrets))
	}
}

func TestGenerateTrusteeConfig_EmptySecrets(t *testing.T) {
	sealedSecrets := []*SealedSecretData{}

	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "trustee-config.json")

	err := GenerateTrusteeConfig(sealedSecrets, outputPath)
	if err != nil {
		t.Fatalf("GenerateTrusteeConfig() failed: %v", err)
	}

	// Read and parse the file
	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("Failed to read output file: %v", err)
	}

	var config TrusteeConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		t.Fatalf("Failed to parse YAML: %v", err)
	}

	if len(config.Secrets) != 0 {
		t.Errorf("Expected 0 secrets in config, got %d", len(config.Secrets))
	}
}

func TestDecodeSealedSecret(t *testing.T) {
	// Valid sealed secret
	sealedSecret := "sealed.fakejwsheader.eyJ2ZXJzaW9uIjoiMC4xLjAiLCJ0eXBlIjoidmF1bHQiLCJuYW1lIjoia2JzOi8vL2RlZmF1bHQvZGItY3JlZHMvcGFzc3dvcmQiLCJwcm92aWRlciI6ImticyIsInByb3ZpZGVyX3NldHRpbmdzIjp7fSwiYW5ub3RhdGlvbnMiOnt9fQ.fakesignature"

	jsonSpec, err := decodeSealedSecret(sealedSecret)
	if err != nil {
		t.Fatalf("decodeSealedSecret() failed: %v", err)
	}

	if jsonSpec["version"] != "0.1.0" {
		t.Errorf("version = %v, want %q", jsonSpec["version"], "0.1.0")
	}

	if jsonSpec["type"] != "vault" {
		t.Errorf("type = %v, want %q", jsonSpec["type"], "vault")
	}

	if jsonSpec["provider"] != "kbs" {
		t.Errorf("provider = %v, want %q", jsonSpec["provider"], "kbs")
	}

	if jsonSpec["name"] != "kbs:///default/db-creds/password" {
		t.Errorf("name = %v, want %q", jsonSpec["name"], "kbs:///default/db-creds/password")
	}
}

func TestDecodeSealedSecret_InvalidFormat(t *testing.T) {
	tests := []struct {
		name   string
		sealed string
	}{
		{
			name:   "missing parts",
			sealed: "sealed.fakejwsheader",
		},
		{
			name:   "invalid base64",
			sealed: "sealed.fakejwsheader.invalid!!base64.fakesignature",
		},
		{
			name:   "empty",
			sealed: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := decodeSealedSecret(tt.sealed)
			if err == nil {
				t.Error("Expected error for invalid sealed secret, got nil")
			}
		})
	}
}
