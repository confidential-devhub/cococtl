package integration_test

import (
	"testing"

	"github.com/confidential-devhub/cococtl/pkg/manifest"
	"github.com/confidential-devhub/cococtl/pkg/secrets"
)

func TestManifest_ConvertEnvSecretToSealed(t *testing.T) {
	m, err := manifest.Load("testdata/manifests/pod-with-env-secret.yaml")
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	sealedSecret := "sealed.fakejwsheader.eyJ2ZXJzaW9uIjoiMC4xLjAifQ.fakesignature"

	err = m.ConvertEnvSecretToSealed("app", "DB_PASSWORD", sealedSecret)
	if err != nil {
		t.Fatalf("ConvertEnvSecretToSealed() failed: %v", err)
	}

	// Verify the transformation
	spec, err := m.GetSpec()
	if err != nil {
		t.Fatalf("GetSpec() failed: %v", err)
	}

	containers, ok := spec["containers"].([]interface{})
	if !ok || len(containers) == 0 {
		t.Fatal("No containers found")
	}

	container, ok := containers[0].(map[string]interface{})
	if !ok {
		t.Fatal("Container is not a map")
	}

	env, ok := container["env"].([]interface{})
	if !ok || len(env) == 0 {
		t.Fatal("No env variables found")
	}

	// Find the DB_PASSWORD env var
	found := false
	for _, e := range env {
		envVar, ok := e.(map[string]interface{})
		if !ok {
			continue
		}

		if envVar["name"] == "DB_PASSWORD" {
			// Verify it now has a value instead of valueFrom
			if _, hasValueFrom := envVar["valueFrom"]; hasValueFrom {
				t.Error("valueFrom still exists after conversion")
			}

			value, ok := envVar["value"].(string)
			if !ok {
				t.Fatal("value is not a string")
			}

			if value != sealedSecret {
				t.Errorf("value = %q, want %q", value, sealedSecret)
			}

			found = true
			break
		}
	}

	if !found {
		t.Error("DB_PASSWORD env variable not found")
	}
}

func TestManifest_ConvertVolumeSecretToInitContainer(t *testing.T) {
	m, err := manifest.Load("testdata/manifests/pod-with-secrets.yaml")
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	sealedSecrets := map[string]string{
		"key1": "sealed.fake1",
		"key2": "sealed.fake2",
	}

	err = m.ConvertVolumeSecretToInitContainer("another-secret", sealedSecrets, "secret-volume", "/mnt/secrets", "fedora:latest")
	if err != nil {
		t.Fatalf("ConvertVolumeSecretToInitContainer() failed: %v", err)
	}

	spec, err := m.GetSpec()
	if err != nil {
		t.Fatalf("GetSpec() failed: %v", err)
	}

	// Verify volume is now emptyDir
	volumes, ok := spec["volumes"].([]interface{})
	if !ok {
		t.Fatal("No volumes found")
	}

	foundEmptyDir := false
	for _, v := range volumes {
		vol, ok := v.(map[string]interface{})
		if !ok {
			continue
		}

		if vol["name"] == "secret-volume" {
			if _, hasEmptyDir := vol["emptyDir"]; hasEmptyDir {
				foundEmptyDir = true
			}
			if _, hasSecret := vol["secret"]; hasSecret {
				t.Error("secret volume type still exists after conversion")
			}
		}
	}

	if !foundEmptyDir {
		t.Error("emptyDir volume not found after conversion")
	}

	// Verify initContainer was added
	initContainers, ok := spec["initContainers"].([]interface{})
	if !ok || len(initContainers) == 0 {
		t.Fatal("No initContainers found after conversion")
	}

	foundInitContainer := false
	for _, ic := range initContainers {
		initContainer, ok := ic.(map[string]interface{})
		if !ok {
			continue
		}

		if name, ok := initContainer["name"].(string); ok && name == "get-secrets-another-secret" {
			foundInitContainer = true

			// Verify image
			if initContainer["image"] != "fedora:latest" {
				t.Errorf("initContainer image = %v, want %q", initContainer["image"], "fedora:latest")
			}

			// Verify volumeMounts
			volumeMounts, ok := initContainer["volumeMounts"].([]interface{})
			if !ok || len(volumeMounts) == 0 {
				t.Error("initContainer has no volumeMounts")
			}
		}
	}

	if !foundInitContainer {
		t.Error("get-secrets-another-secret initContainer not found")
	}
}

func TestManifest_ConvertEnvFromSecret(t *testing.T) {
	m, err := manifest.Load("testdata/manifests/pod-with-envfrom-secret.yaml")
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	sealedSecretsMap := map[string]string{
		"API_KEY":   "sealed.fake.apikey",
		"DB_HOST":   "sealed.fake.dbhost",
		"LOG_LEVEL": "sealed.fake.loglevel",
	}

	err = m.ConvertEnvFromSecret("app", "config-secret", sealedSecretsMap)
	if err != nil {
		t.Fatalf("ConvertEnvFromSecret() failed: %v", err)
	}

	spec, err := m.GetSpec()
	if err != nil {
		t.Fatalf("GetSpec() failed: %v", err)
	}

	containers, ok := spec["containers"].([]interface{})
	if !ok || len(containers) == 0 {
		t.Fatal("No containers found")
	}

	container, ok := containers[0].(map[string]interface{})
	if !ok {
		t.Fatal("Container is not a map")
	}

	// Verify envFrom was removed or modified
	if envFrom, ok := container["envFrom"].([]interface{}); ok {
		for _, ef := range envFrom {
			efMap, ok := ef.(map[string]interface{})
			if !ok {
				continue
			}

			if secretRef, ok := efMap["secretRef"].(map[string]interface{}); ok {
				if secretRef["name"] == "config-secret" {
					t.Error("envFrom secretRef for config-secret still exists")
				}
			}
		}
	}

	// Verify individual env vars were added
	env, ok := container["env"].([]interface{})
	if !ok {
		t.Fatal("No env variables found")
	}

	foundKeys := make(map[string]bool)
	for _, e := range env {
		envVar, ok := e.(map[string]interface{})
		if !ok {
			continue
		}

		name, ok := envVar["name"].(string)
		if !ok {
			continue
		}

		if expectedValue, exists := sealedSecretsMap[name]; exists {
			if value, ok := envVar["value"].(string); ok && value == expectedValue {
				foundKeys[name] = true
			}
		}
	}

	for key := range sealedSecretsMap {
		if !foundKeys[key] {
			t.Errorf("Env variable %q not found or has incorrect value", key)
		}
	}
}

func TestManifest_RemoveSecretVolume(t *testing.T) {
	m, err := manifest.Load("testdata/manifests/pod-with-secrets.yaml")
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	err = m.RemoveSecretVolume("secret-volume")
	if err != nil {
		t.Fatalf("RemoveSecretVolume() failed: %v", err)
	}

	spec, err := m.GetSpec()
	if err != nil {
		t.Fatalf("GetSpec() failed: %v", err)
	}

	volumes, ok := spec["volumes"].([]interface{})
	if !ok {
		// No volumes is fine
		return
	}

	// Verify the volume was removed
	for _, v := range volumes {
		vol, ok := v.(map[string]interface{})
		if !ok {
			continue
		}

		if vol["name"] == "secret-volume" {
			t.Error("secret-volume was not removed")
		}
	}
}

func TestSecrets_DetectSecrets_IntegrationManifests(t *testing.T) {
	tests := []struct {
		name          string
		manifestPath  string
		expectedCount int
	}{
		{
			name:          "env secrets",
			manifestPath:  "testdata/manifests/pod-with-env-secret.yaml",
			expectedCount: 2, // db-creds and api-secret
		},
		{
			name:          "volume and env secrets",
			manifestPath:  "testdata/manifests/pod-with-secrets.yaml",
			expectedCount: 2, // my-secret and another-secret
		},
		{
			name:          "envFrom secrets",
			manifestPath:  "testdata/manifests/pod-with-envfrom-secret.yaml",
			expectedCount: 1, // config-secret
		},
		{
			name:          "mixed secrets",
			manifestPath:  "testdata/manifests/pod-with-mixed-secrets.yaml",
			expectedCount: 3, // db-creds, app-config, tls-secret
		},
		{
			name:          "no secrets",
			manifestPath:  "testdata/manifests/simple-pod.yaml",
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := manifest.Load(tt.manifestPath)
			if err != nil {
				t.Fatalf("Load() failed: %v", err)
			}

			refs, err := secrets.DetectSecrets(m.GetData())
			if err != nil {
				t.Fatalf("DetectSecrets() failed: %v", err)
			}

			if len(refs) != tt.expectedCount {
				t.Errorf("Expected %d secrets, got %d", tt.expectedCount, len(refs))
			}
		})
	}
}

func TestSecrets_ConvertToSealed_Integration(t *testing.T) {
	refs := []secrets.SecretReference{
		{
			Name:      "db-creds",
			Namespace: "default",
			Keys:      []string{"password", "username"},
		},
	}

	sealed, err := secrets.ConvertSecrets(refs, nil)
	if err != nil {
		t.Fatalf("ConvertSecrets() failed: %v", err)
	}

	if len(sealed) != 2 {
		t.Fatalf("Expected 2 sealed secrets, got %d", len(sealed))
	}

	// Verify each sealed secret has the correct structure
	for _, s := range sealed {
		if s.ResourceURI == "" {
			t.Error("ResourceURI is empty")
		}

		if s.SealedSecret == "" {
			t.Error("SealedSecret is empty")
		}

		if s.SecretName != "db-creds" {
			t.Errorf("SecretName = %q, want %q", s.SecretName, "db-creds")
		}

		if s.Namespace != "default" {
			t.Errorf("Namespace = %q, want %q", s.Namespace, "default")
		}
	}
}
