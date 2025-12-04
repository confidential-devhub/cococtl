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
		{
			name:          "deployment with secrets",
			manifestPath:  "testdata/manifests/deployment-with-secrets.yaml",
			expectedCount: 3, // db-credentials, api-secrets, tls-cert
		},
		{
			name:          "deployment with secrets and imagePullSecrets",
			manifestPath:  "testdata/manifests/deployment-with-secrets-and-imagepullsecrets.yaml",
			expectedCount: 3, // db-creds, api-creds, regcred
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

func TestManifest_GetImagePullSecrets(t *testing.T) {
	m, err := manifest.Load("testdata/manifests/pod-with-imagepullsecrets.yaml")
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	imagePullSecrets := m.GetImagePullSecrets()
	if len(imagePullSecrets) != 1 {
		t.Fatalf("Expected 1 imagePullSecret, got %d", len(imagePullSecrets))
	}

	if imagePullSecrets[0] != "regcred" {
		t.Errorf("imagePullSecret name = %q, want %q", imagePullSecrets[0], "regcred")
	}
}

func TestManifest_RemoveImagePullSecrets(t *testing.T) {
	m, err := manifest.Load("testdata/manifests/pod-with-imagepullsecrets.yaml")
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// Verify imagePullSecrets exist before removal
	imagePullSecretsBefore := m.GetImagePullSecrets()
	if len(imagePullSecretsBefore) == 0 {
		t.Fatal("No imagePullSecrets found in test manifest")
	}

	// Remove imagePullSecrets
	err = m.RemoveImagePullSecrets()
	if err != nil {
		t.Fatalf("RemoveImagePullSecrets() failed: %v", err)
	}

	// Verify imagePullSecrets were removed
	imagePullSecretsAfter := m.GetImagePullSecrets()
	if len(imagePullSecretsAfter) != 0 {
		t.Errorf("Expected 0 imagePullSecrets after removal, got %d", len(imagePullSecretsAfter))
	}

	// Verify in podSpec directly
	podSpec, err := m.GetPodSpec()
	if err != nil {
		t.Fatalf("GetPodSpec() failed: %v", err)
	}

	if _, exists := podSpec["imagePullSecrets"]; exists {
		t.Error("imagePullSecrets field still exists in podSpec after removal")
	}
}

func TestSecrets_DetectImagePullSecrets(t *testing.T) {
	m, err := manifest.Load("testdata/manifests/pod-with-imagepullsecrets.yaml")
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	refs, err := secrets.DetectSecrets(m.GetData())
	if err != nil {
		t.Fatalf("DetectSecrets() failed: %v", err)
	}

	// Should detect 1 secret (regcred)
	if len(refs) != 1 {
		t.Fatalf("Expected 1 secret, got %d", len(refs))
	}

	// Verify it's detected as imagePullSecrets type
	if refs[0].Name != "regcred" {
		t.Errorf("Secret name = %q, want %q", refs[0].Name, "regcred")
	}

	// Verify usage type
	foundImagePullSecret := false
	for _, usage := range refs[0].Usages {
		if usage.Type == "imagePullSecrets" {
			foundImagePullSecret = true
			break
		}
	}

	if !foundImagePullSecret {
		t.Error("imagePullSecrets usage type not found")
	}

	// Verify NeedsLookup is true (we need to inspect the secret for keys)
	if !refs[0].NeedsLookup {
		t.Error("NeedsLookup should be true for imagePullSecrets")
	}
}

func TestSecrets_DetectMultipleImagePullSecrets(t *testing.T) {
	m, err := manifest.Load("testdata/manifests/pod-with-multiple-imagepullsecrets.yaml")
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	refs, err := secrets.DetectSecrets(m.GetData())
	if err != nil {
		t.Fatalf("DetectSecrets() failed: %v", err)
	}

	// Should detect 3 secrets (regcred-first, regcred-second, regcred-third)
	if len(refs) != 3 {
		t.Fatalf("Expected 3 secrets, got %d", len(refs))
	}

	// Verify all are detected as imagePullSecrets type
	expectedNames := map[string]bool{
		"regcred-first":  false,
		"regcred-second": false,
		"regcred-third":  false,
	}

	for _, ref := range refs {
		if _, exists := expectedNames[ref.Name]; exists {
			expectedNames[ref.Name] = true

			// Verify it has imagePullSecrets usage
			foundImagePullSecret := false
			for _, usage := range ref.Usages {
				if usage.Type == "imagePullSecrets" {
					foundImagePullSecret = true
					break
				}
			}

			if !foundImagePullSecret {
				t.Errorf("Secret %s does not have imagePullSecrets usage type", ref.Name)
			}
		}
	}

	// Verify all expected secrets were found
	for name, found := range expectedNames {
		if !found {
			t.Errorf("Expected secret %s not found", name)
		}
	}
}

func TestSecrets_DetectSecretsAndImagePullSecrets_Separately(t *testing.T) {
	m, err := manifest.Load("testdata/manifests/pod-with-secrets-and-imagepullsecrets.yaml")
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	refs, err := secrets.DetectSecrets(m.GetData())
	if err != nil {
		t.Fatalf("DetectSecrets() failed: %v", err)
	}

	// Should detect 2 secrets total: db-creds (env) and regcred (imagePullSecrets)
	if len(refs) != 2 {
		t.Fatalf("Expected 2 secrets, got %d", len(refs))
	}

	// Verify that we can distinguish between regular secrets and imagePullSecrets
	var regularSecrets []secrets.SecretReference
	var imagePullSecrets []secrets.SecretReference

	for _, ref := range refs {
		isImagePullSecret := false
		for _, usage := range ref.Usages {
			if usage.Type == "imagePullSecrets" {
				isImagePullSecret = true
				break
			}
		}

		if isImagePullSecret {
			imagePullSecrets = append(imagePullSecrets, ref)
		} else {
			regularSecrets = append(regularSecrets, ref)
		}
	}

	// Verify counts
	if len(regularSecrets) != 1 {
		t.Errorf("Expected 1 regular secret, got %d", len(regularSecrets))
	}

	if len(imagePullSecrets) != 1 {
		t.Errorf("Expected 1 imagePullSecret, got %d", len(imagePullSecrets))
	}

	// Verify the regular secret is db-creds
	if len(regularSecrets) > 0 && regularSecrets[0].Name != "db-creds" {
		t.Errorf("Regular secret name = %q, want %q", regularSecrets[0].Name, "db-creds")
	}

	// Verify the imagePullSecret is regcred
	if len(imagePullSecrets) > 0 && imagePullSecrets[0].Name != "regcred" {
		t.Errorf("ImagePullSecret name = %q, want %q", imagePullSecrets[0].Name, "regcred")
	}
}
