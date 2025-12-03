package integration_test

import (
	"encoding/json"
	"testing"

	"github.com/confidential-devhub/cococtl/pkg/trustee"
)

func TestConvertDockercfgToDockerConfigJSON(t *testing.T) {
	// Sample .dockercfg format
	dockercfgData := `{
		"https://index.docker.io/v1/": {
			"auth": "dXNlcm5hbWU6cGFzc3dvcmQ=",
			"email": "user@example.com"
		},
		"quay.io": {
			"auth": "YW5vdGhlcjphdXRo"
		}
	}`

	// Parse as raw map to verify structure
	var oldFormat map[string]interface{}
	if err := json.Unmarshal([]byte(dockercfgData), &oldFormat); err != nil {
		t.Fatalf("Failed to parse test dockercfg data: %v", err)
	}

	// Verify the old format doesn't have "auths" key
	if _, hasAuths := oldFormat["auths"]; hasAuths {
		t.Fatal("Test data should not have 'auths' key (old format)")
	}

	// Convert to dockerconfigjson format
	convertedData, err := trustee.ConvertDockercfgToDockerConfigJSON([]byte(dockercfgData))
	if err != nil {
		t.Fatalf("ConvertDockercfgToDockerConfigJSON() failed: %v", err)
	}

	// Parse the converted data
	var newFormat map[string]interface{}
	if err := json.Unmarshal(convertedData, &newFormat); err != nil {
		t.Fatalf("Failed to parse converted data: %v", err)
	}

	// Verify the new format has "auths" key
	auths, hasAuths := newFormat["auths"]
	if !hasAuths {
		t.Fatal("Converted data should have 'auths' key")
	}

	// Verify the auths structure
	authsMap, ok := auths.(map[string]interface{})
	if !ok {
		t.Fatal("'auths' should be a map")
	}

	// Verify the registries are present in auths
	if _, hasDockerHub := authsMap["https://index.docker.io/v1/"]; !hasDockerHub {
		t.Error("Converted data should have Docker Hub registry in auths")
	}

	if _, hasQuay := authsMap["quay.io"]; !hasQuay {
		t.Error("Converted data should have Quay.io registry in auths")
	}

	// Verify the auth values are preserved
	dockerHub, _ := authsMap["https://index.docker.io/v1/"].(map[string]interface{})
	if auth, ok := dockerHub["auth"].(string); !ok || auth != "dXNlcm5hbWU6cGFzc3dvcmQ=" {
		t.Errorf("Docker Hub auth not preserved correctly, got: %v", dockerHub["auth"])
	}

	if email, ok := dockerHub["email"].(string); !ok || email != "user@example.com" {
		t.Errorf("Docker Hub email not preserved correctly, got: %v", dockerHub["email"])
	}

	quay, _ := authsMap["quay.io"].(map[string]interface{})
	if auth, ok := quay["auth"].(string); !ok || auth != "YW5vdGhlcjphdXRo" {
		t.Errorf("Quay.io auth not preserved correctly, got: %v", quay["auth"])
	}
}

func TestConvertDockercfgToDockerConfigJSON_InvalidJSON(t *testing.T) {
	invalidData := []byte("not valid json")

	_, err := trustee.ConvertDockercfgToDockerConfigJSON(invalidData)
	if err == nil {
		t.Error("Expected error for invalid JSON, got nil")
	}
}

func TestConvertDockercfgToDockerConfigJSON_EmptyData(t *testing.T) {
	emptyData := []byte("{}")

	convertedData, err := trustee.ConvertDockercfgToDockerConfigJSON(emptyData)
	if err != nil {
		t.Fatalf("ConvertDockercfgToDockerConfigJSON() failed for empty data: %v", err)
	}

	// Parse the converted data
	var newFormat map[string]interface{}
	if err := json.Unmarshal(convertedData, &newFormat); err != nil {
		t.Fatalf("Failed to parse converted data: %v", err)
	}

	// Verify the new format has "auths" key
	auths, hasAuths := newFormat["auths"]
	if !hasAuths {
		t.Fatal("Converted data should have 'auths' key even when empty")
	}

	authsMap, ok := auths.(map[string]interface{})
	if !ok {
		t.Fatal("'auths' should be a map")
	}

	if len(authsMap) != 0 {
		t.Errorf("Expected empty auths map, got %d entries", len(authsMap))
	}
}
