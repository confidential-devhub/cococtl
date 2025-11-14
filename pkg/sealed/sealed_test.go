package sealed

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// TestJSONFieldNames ensures the JSON field names match the CoCo specification.
// This test is critical to prevent linters from changing snake_case to camelCase.
// The CoCo sealed secret spec requires "provider_settings" (snake_case).
func TestJSONFieldNames(t *testing.T) {
	uri := "kbs:///default/mysecret/key1"

	secret, err := GenerateSealedSecret(uri)
	if err != nil {
		t.Fatalf("GenerateSealedSecret() failed: %v", err)
	}

	// Extract and decode payload
	parts := strings.Split(secret, ".")
	if len(parts) != 4 {
		t.Fatalf("Expected 4 parts in sealed secret, got %d", len(parts))
	}

	jsonData, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("Failed to decode payload: %v", err)
	}

	// Convert to string to check raw JSON field names
	jsonStr := string(jsonData)

	// CRITICAL: Verify provider_settings (snake_case) is present
	if !strings.Contains(jsonStr, `"provider_settings"`) {
		t.Errorf("JSON does not contain 'provider_settings' field (required by CoCo spec). Got: %s", jsonStr)
	}

	// CRITICAL: Ensure it's NOT using camelCase (common linter mistake)
	if strings.Contains(jsonStr, `"providerSettings"`) {
		t.Errorf("JSON incorrectly uses 'providerSettings' (camelCase) instead of 'provider_settings' (snake_case). Got: %s", jsonStr)
	}

	// Also verify other expected fields
	expectedFields := []string{`"version"`, `"type"`, `"name"`, `"provider"`, `"annotations"`}
	for _, field := range expectedFields {
		if !strings.Contains(jsonStr, field) {
			t.Errorf("JSON missing expected field %s. Got: %s", field, jsonStr)
		}
	}
}

// TestSecretSpecMarshaling verifies the SecretSpec marshals correctly to JSON.
func TestSecretSpecMarshaling(t *testing.T) {
	spec := SecretSpec{
		Version:          "0.1.0",
		Type:             "vault",
		Name:             "kbs:///test/secret/key",
		Provider:         "kbs",
		ProviderSettings: map[string]interface{}{"key": "value"},
		Annotations:      map[string]interface{}{"anno": "test"},
	}

	jsonData, err := json.Marshal(spec)
	if err != nil {
		t.Fatalf("Failed to marshal SecretSpec: %v", err)
	}

	jsonStr := string(jsonData)

	// Verify the JSON structure matches CoCo spec
	if !strings.Contains(jsonStr, `"provider_settings"`) {
		t.Errorf("Marshaled JSON missing 'provider_settings'. Got: %s", jsonStr)
	}

	// Unmarshal back to verify round-trip
	var decoded SecretSpec
	err = json.Unmarshal(jsonData, &decoded)
	if err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	if decoded.Version != spec.Version {
		t.Errorf("Version = %q, want %q", decoded.Version, spec.Version)
	}
	if decoded.Provider != spec.Provider {
		t.Errorf("Provider = %q, want %q", decoded.Provider, spec.Provider)
	}
}

// TestGenerateSealedSecretFormat verifies the basic format structure.
func TestGenerateSealedSecretFormat(t *testing.T) {
	uri := "kbs:///default/test/key"

	secret, err := GenerateSealedSecret(uri)
	if err != nil {
		t.Fatalf("GenerateSealedSecret() failed: %v", err)
	}

	// Verify format: sealed.fakejwsheader.{base64url}.fakesignature
	parts := strings.Split(secret, ".")
	if len(parts) != 4 {
		t.Fatalf("Expected 4 parts, got %d: %s", len(parts), secret)
	}

	if parts[0] != "sealed" {
		t.Errorf("parts[0] = %q, want %q", parts[0], "sealed")
	}
	if parts[1] != "fakejwsheader" {
		t.Errorf("parts[1] = %q, want %q", parts[1], "fakejwsheader")
	}
	if parts[3] != "fakesignature" {
		t.Errorf("parts[3] = %q, want %q", parts[3], "fakesignature")
	}

	// Verify payload is valid base64url
	if parts[2] == "" {
		t.Fatal("Payload is empty")
	}
}
