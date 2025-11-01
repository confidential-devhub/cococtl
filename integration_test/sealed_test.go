package integration_test

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/confidential-devhub/cococtl/pkg/sealed"
)

func TestSealed_Generate_ValidKBSURI(t *testing.T) {
	uri := "kbs:///default/mysecret/key1"

	secret, err := sealed.GenerateSealedSecret(uri)
	if err != nil {
		t.Fatalf("GenerateSealedSecret() failed: %v", err)
	}

	// Verify format: sealed.fakejwsheader.{base64url}.fakesignature
	parts := strings.Split(secret, ".")
	if len(parts) != 4 {
		t.Fatalf("Expected 4 parts in sealed secret, got %d: %s", len(parts), secret)
	}

	if parts[0] != "sealed" {
		t.Errorf("First part = %q, want %q", parts[0], "sealed")
	}
	if parts[1] != "fakejwsheader" {
		t.Errorf("Second part = %q, want %q", parts[1], "fakejwsheader")
	}
	if parts[3] != "fakesignature" {
		t.Errorf("Fourth part = %q, want %q", parts[3], "fakesignature")
	}

	// Verify the payload is valid base64url
	payload := parts[2]
	if payload == "" {
		t.Fatal("Payload is empty")
	}

	// Decode and verify JSON structure
	jsonData, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		t.Fatalf("Failed to decode base64url payload: %v", err)
	}

	var spec sealed.SecretSpec
	err = json.Unmarshal(jsonData, &spec)
	if err != nil {
		t.Fatalf("Failed to unmarshal JSON payload: %v", err)
	}

	// Verify fields
	if spec.Version != "0.1.0" {
		t.Errorf("Version = %q, want %q", spec.Version, "0.1.0")
	}
	if spec.Type != "vault" {
		t.Errorf("Type = %q, want %q", spec.Type, "vault")
	}
	if spec.Provider != "kbs" {
		t.Errorf("Provider = %q, want %q", spec.Provider, "kbs")
	}
	if spec.Name != uri {
		t.Errorf("Name = %q, want %q", spec.Name, uri)
	}
}

func TestSealed_Generate_MultipleURIs(t *testing.T) {
	tests := []struct {
		name string
		uri  string
	}{
		{"URI 1", "kbs:///default/secret1/key1"},
		{"URI 2", "kbs:///production/secret2/apikey"},
		{"URI 3", "kbs:///staging/db-creds/password"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secret, err := sealed.GenerateSealedSecret(tt.uri)
			if err != nil {
				t.Fatalf("GenerateSealedSecret() failed for %s: %v", tt.uri, err)
			}

			// Extract and decode payload
			parts := strings.Split(secret, ".")
			jsonData, err := base64.RawURLEncoding.DecodeString(parts[2])
			if err != nil {
				t.Fatalf("Failed to decode payload: %v", err)
			}

			var spec sealed.SecretSpec
			err = json.Unmarshal(jsonData, &spec)
			if err != nil {
				t.Fatalf("Failed to unmarshal JSON: %v", err)
			}

			if spec.Name != tt.uri {
				t.Errorf("Name = %q, want %q", spec.Name, tt.uri)
			}
		})
	}
}

func TestSealed_Format_Base64URLEncoding(t *testing.T) {
	uri := "kbs:///default/mysecret/key1"

	secret, err := sealed.GenerateSealedSecret(uri)
	if err != nil {
		t.Fatalf("GenerateSealedSecret() failed: %v", err)
	}

	// Extract payload
	parts := strings.Split(secret, ".")
	payload := parts[2]

	// Verify no padding (base64url unpadded)
	if strings.Contains(payload, "=") {
		t.Error("Payload contains padding '=', expected unpadded base64url")
	}

	// Verify base64url alphabet (should not contain + or /)
	if strings.Contains(payload, "+") {
		t.Error("Payload contains '+', expected base64url encoding")
	}
	if strings.Contains(payload, "/") {
		t.Error("Payload contains '/', expected base64url encoding")
	}

	// Verify it decodes successfully
	_, err = base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		t.Errorf("Failed to decode base64url payload: %v", err)
	}
}

func TestSealed_Payload_JSONStructure(t *testing.T) {
	uri := "kbs:///default/mysecret/key1"

	secret, err := sealed.GenerateSealedSecret(uri)
	if err != nil {
		t.Fatalf("GenerateSealedSecret() failed: %v", err)
	}

	// Extract and decode payload
	parts := strings.Split(secret, ".")
	jsonData, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("Failed to decode payload: %v", err)
	}

	var spec sealed.SecretSpec
	err = json.Unmarshal(jsonData, &spec)
	if err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	// Verify all required fields are present
	if spec.Version == "" {
		t.Error("Version is empty")
	}
	if spec.Type == "" {
		t.Error("Type is empty")
	}
	if spec.Name == "" {
		t.Error("Name is empty")
	}
	if spec.Provider == "" {
		t.Error("Provider is empty")
	}
	if spec.ProviderSettings == nil {
		t.Error("ProviderSettings is nil")
	}
	if spec.Annotations == nil {
		t.Error("Annotations is nil")
	}
}

func TestSealed_ParseResourceURI_ValidURI(t *testing.T) {
	tests := []struct {
		name              string
		uri               string
		expectedNamespace string
		expectedResource  string
		expectedKey       string
		expectError       bool
	}{
		{
			name:              "Standard URI",
			uri:               "kbs:///default/mysecret/key1",
			expectedNamespace: "default",
			expectedResource:  "mysecret",
			expectedKey:       "key1",
			expectError:       false,
		},
		{
			name:              "Production namespace",
			uri:               "kbs:///production/db-creds/password",
			expectedNamespace: "production",
			expectedResource:  "db-creds",
			expectedKey:       "password",
			expectError:       false,
		},
		{
			name:        "Missing kbs prefix",
			uri:         "default/mysecret/key1",
			expectError: true,
		},
		{
			name:        "Incomplete URI",
			uri:         "kbs:///default/mysecret",
			expectError: true,
		},
		{
			name:        "Empty URI",
			uri:         "kbs:///",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			namespace, resource, key, err := sealed.ParseResourceURI(tt.uri)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if namespace != tt.expectedNamespace {
				t.Errorf("Namespace = %q, want %q", namespace, tt.expectedNamespace)
			}
			if resource != tt.expectedResource {
				t.Errorf("Resource = %q, want %q", resource, tt.expectedResource)
			}
			if key != tt.expectedKey {
				t.Errorf("Key = %q, want %q", key, tt.expectedKey)
			}
		})
	}
}
