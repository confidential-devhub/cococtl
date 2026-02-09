package secrets

import (
	"strings"
	"testing"
)

func TestConvertToSealed(t *testing.T) {
	// kbsNamespace "default" for URI; k8sNamespace "my-app" for K8s resource
	sealed, err := ConvertToSealed("default", "my-app", "db-creds", "password")
	if err != nil {
		t.Fatalf("ConvertToSealed() failed: %v", err)
	}

	if sealed.ResourceURI != "kbs:///default/db-creds/password" {
		t.Errorf("ResourceURI = %q, want %q", sealed.ResourceURI, "kbs:///default/db-creds/password")
	}

	if sealed.SecretName != "db-creds" {
		t.Errorf("SecretName = %q, want %q", sealed.SecretName, "db-creds")
	}

	if sealed.Key != "password" {
		t.Errorf("Key = %q, want %q", sealed.Key, "password")
	}

	// Namespace is K8s resource namespace (from input manifest)
	if sealed.Namespace != "my-app" {
		t.Errorf("Namespace = %q, want %q", sealed.Namespace, "my-app")
	}

	// Verify sealed secret format
	if !strings.HasPrefix(sealed.SealedSecret, "sealed.fakejwsheader.") {
		t.Errorf("SealedSecret doesn't have correct prefix: %s", sealed.SealedSecret)
	}

	if !strings.HasSuffix(sealed.SealedSecret, ".fakesignature") {
		t.Errorf("SealedSecret doesn't have correct suffix: %s", sealed.SealedSecret)
	}
}

func TestConvertSecrets_WithKnownKeys(t *testing.T) {
	refs := []SecretReference{
		{
			Name:      "db-creds",
			Namespace: "default",
			Keys:      []string{"password", "username"},
			Usages: []SecretUsage{
				{Type: "env", Key: "password"},
				{Type: "env", Key: "username"},
			},
		},
	}

	sealed, err := ConvertSecrets(refs, nil)
	if err != nil {
		t.Fatalf("ConvertSecrets() failed: %v", err)
	}

	if len(sealed) != 2 {
		t.Fatalf("Expected 2 sealed secrets, got %d", len(sealed))
	}

	// Verify both keys were converted
	foundPassword := false
	foundUsername := false
	for _, s := range sealed {
		if s.Key == "password" {
			foundPassword = true
		}
		if s.Key == "username" {
			foundUsername = true
		}
	}

	if !foundPassword {
		t.Error("Missing sealed secret for 'password' key")
	}

	if !foundUsername {
		t.Error("Missing sealed secret for 'username' key")
	}
}

func TestConvertSecrets_WithInspectedKeys(t *testing.T) {
	refs := []SecretReference{
		{
			Name:        "app-config",
			Namespace:   "",         // No namespace in manifest
			Keys:        []string{}, // No known keys
			NeedsLookup: true,
			Usages: []SecretUsage{
				{Type: "envFrom"},
			},
		},
	}

	inspectedKeys := map[string]*SecretKeys{
		"app-config": {
			Name:      "app-config",
			Namespace: "production",
			Keys:      []string{"API_KEY", "DB_HOST", "LOG_LEVEL"},
		},
	}

	sealed, err := ConvertSecrets(refs, inspectedKeys)
	if err != nil {
		t.Fatalf("ConvertSecrets() failed: %v", err)
	}

	if len(sealed) != 3 {
		t.Fatalf("Expected 3 sealed secrets, got %d", len(sealed))
	}

	// Verify all keys were converted
	keys := make(map[string]bool)
	for _, s := range sealed {
		keys[s.Key] = true
		// K8s namespace is from input manifest (ref.Namespace); ref had empty so we use "default"
		if s.Namespace != "default" {
			t.Errorf("Expected namespace 'default' (from manifest), got %q", s.Namespace)
		}
		// KBS URI always uses "default"
		if s.ResourceURI != "kbs:///default/app-config/"+s.Key {
			t.Errorf("Expected ResourceURI kbs:///default/app-config/%s, got %q", s.Key, s.ResourceURI)
		}
	}

	expected := []string{"API_KEY", "DB_HOST", "LOG_LEVEL"}
	for _, key := range expected {
		if !keys[key] {
			t.Errorf("Missing sealed secret for key %q", key)
		}
	}
}

func TestConvertSecrets_NoKeysAvailable(t *testing.T) {
	refs := []SecretReference{
		{
			Name:        "app-config",
			Namespace:   "default",
			Keys:        []string{}, // No known keys
			NeedsLookup: true,
		},
	}

	// No inspected keys either
	_, err := ConvertSecrets(refs, nil)
	if err == nil {
		t.Error("Expected error when no keys available, got nil")
	}

	if !strings.Contains(err.Error(), "no keys found") {
		t.Errorf("Expected error about no keys, got: %v", err)
	}
}

func TestConvertSecrets_MultipleSecrets(t *testing.T) {
	refs := []SecretReference{
		{
			Name:      "db-creds",
			Namespace: "default",
			Keys:      []string{"password"},
		},
		{
			Name:      "api-keys",
			Namespace: "production",
			Keys:      []string{"api-key"},
		},
	}

	sealed, err := ConvertSecrets(refs, nil)
	if err != nil {
		t.Fatalf("ConvertSecrets() failed: %v", err)
	}

	if len(sealed) != 2 {
		t.Fatalf("Expected 2 sealed secrets, got %d", len(sealed))
	}

	// Verify namespaces are correct
	for _, s := range sealed {
		if s.SecretName == "db-creds" && s.Namespace != "default" {
			t.Errorf("db-creds namespace = %q, want %q", s.Namespace, "default")
		}
		if s.SecretName == "api-keys" && s.Namespace != "production" {
			t.Errorf("api-keys namespace = %q, want %q", s.Namespace, "production")
		}
	}
}
