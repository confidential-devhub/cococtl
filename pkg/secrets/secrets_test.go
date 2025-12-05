package secrets

import (
	"testing"

	"github.com/confidential-devhub/cococtl/pkg/manifest"
)

func TestDetectSecrets_EnvSecrets(t *testing.T) {
	manifest := map[string]interface{}{
		"metadata": map[string]interface{}{
			"name":      "test-pod",
			"namespace": "default",
		},
		"spec": map[string]interface{}{
			"containers": []interface{}{
				map[string]interface{}{
					"name":  "app",
					"image": "nginx",
					"env": []interface{}{
						map[string]interface{}{
							"name": "DB_PASSWORD",
							"valueFrom": map[string]interface{}{
								"secretKeyRef": map[string]interface{}{
									"name": "db-creds",
									"key":  "password",
								},
							},
						},
					},
				},
			},
		},
	}

	refs, err := DetectSecrets(manifest)
	if err != nil {
		t.Fatalf("DetectSecrets() failed: %v", err)
	}

	if len(refs) != 1 {
		t.Fatalf("Expected 1 secret reference, got %d", len(refs))
	}

	ref := refs[0]
	if ref.Name != "db-creds" {
		t.Errorf("Secret name = %q, want %q", ref.Name, "db-creds")
	}

	if ref.Namespace != "default" {
		t.Errorf("Namespace = %q, want %q", ref.Namespace, "default")
	}

	if len(ref.Keys) != 1 || ref.Keys[0] != "password" {
		t.Errorf("Keys = %v, want [password]", ref.Keys)
	}

	if len(ref.Usages) != 1 {
		t.Fatalf("Expected 1 usage, got %d", len(ref.Usages))
	}

	usage := ref.Usages[0]
	if usage.Type != "env" {
		t.Errorf("Usage type = %q, want %q", usage.Type, "env")
	}

	if usage.EnvVarName != "DB_PASSWORD" {
		t.Errorf("EnvVarName = %q, want %q", usage.EnvVarName, "DB_PASSWORD")
	}

	if usage.Key != "password" {
		t.Errorf("Usage key = %q, want %q", usage.Key, "password")
	}
}

func TestDetectSecrets_VolumeSecrets(t *testing.T) {
	manifest := map[string]interface{}{
		"metadata": map[string]interface{}{
			"name": "test-pod",
		},
		"spec": map[string]interface{}{
			"containers": []interface{}{
				map[string]interface{}{
					"name":  "app",
					"image": "nginx",
					"volumeMounts": []interface{}{
						map[string]interface{}{
							"name":      "certs",
							"mountPath": "/etc/certs",
						},
					},
				},
			},
			"volumes": []interface{}{
				map[string]interface{}{
					"name": "certs",
					"secret": map[string]interface{}{
						"secretName": "tls-secret",
					},
				},
			},
		},
	}

	refs, err := DetectSecrets(manifest)
	if err != nil {
		t.Fatalf("DetectSecrets() failed: %v", err)
	}

	if len(refs) != 1 {
		t.Fatalf("Expected 1 secret reference, got %d", len(refs))
	}

	ref := refs[0]
	if ref.Name != "tls-secret" {
		t.Errorf("Secret name = %q, want %q", ref.Name, "tls-secret")
	}

	if !ref.NeedsLookup {
		t.Error("NeedsLookup should be true for volume secret without items")
	}

	if len(ref.Usages) != 1 {
		t.Fatalf("Expected 1 usage, got %d", len(ref.Usages))
	}

	usage := ref.Usages[0]
	if usage.Type != "volume" {
		t.Errorf("Usage type = %q, want %q", usage.Type, "volume")
	}

	if usage.VolumeName != "certs" {
		t.Errorf("VolumeName = %q, want %q", usage.VolumeName, "certs")
	}

	if usage.MountPath != "/etc/certs" {
		t.Errorf("MountPath = %q, want %q", usage.MountPath, "/etc/certs")
	}
}

func TestDetectSecrets_VolumeWithItems(t *testing.T) {
	manifest := map[string]interface{}{
		"metadata": map[string]interface{}{
			"name": "test-pod",
		},
		"spec": map[string]interface{}{
			"containers": []interface{}{
				map[string]interface{}{
					"name":  "app",
					"image": "nginx",
				},
			},
			"volumes": []interface{}{
				map[string]interface{}{
					"name": "certs",
					"secret": map[string]interface{}{
						"secretName": "tls-secret",
						"items": []interface{}{
							map[string]interface{}{
								"key":  "tls.crt",
								"path": "server.crt",
							},
							map[string]interface{}{
								"key":  "tls.key",
								"path": "server.key",
							},
						},
					},
				},
			},
		},
	}

	refs, err := DetectSecrets(manifest)
	if err != nil {
		t.Fatalf("DetectSecrets() failed: %v", err)
	}

	if len(refs) != 1 {
		t.Fatalf("Expected 1 secret reference, got %d", len(refs))
	}

	ref := refs[0]
	if ref.NeedsLookup {
		t.Error("NeedsLookup should be false when items are specified")
	}

	if len(ref.Keys) != 2 {
		t.Fatalf("Expected 2 keys, got %d", len(ref.Keys))
	}

	// Verify keys (order may vary)
	hasKey := func(keys []string, key string) bool {
		for _, k := range keys {
			if k == key {
				return true
			}
		}
		return false
	}

	if !hasKey(ref.Keys, "tls.crt") {
		t.Error("Missing key 'tls.crt'")
	}

	if !hasKey(ref.Keys, "tls.key") {
		t.Error("Missing key 'tls.key'")
	}
}

func TestDetectSecrets_EnvFromSecrets(t *testing.T) {
	manifest := map[string]interface{}{
		"metadata": map[string]interface{}{
			"name": "test-pod",
		},
		"spec": map[string]interface{}{
			"containers": []interface{}{
				map[string]interface{}{
					"name":  "app",
					"image": "nginx",
					"envFrom": []interface{}{
						map[string]interface{}{
							"secretRef": map[string]interface{}{
								"name": "app-config",
							},
						},
					},
				},
			},
		},
	}

	refs, err := DetectSecrets(manifest)
	if err != nil {
		t.Fatalf("DetectSecrets() failed: %v", err)
	}

	if len(refs) != 1 {
		t.Fatalf("Expected 1 secret reference, got %d", len(refs))
	}

	ref := refs[0]
	if ref.Name != "app-config" {
		t.Errorf("Secret name = %q, want %q", ref.Name, "app-config")
	}

	if !ref.NeedsLookup {
		t.Error("NeedsLookup should be true for envFrom secret")
	}

	if len(ref.Usages) != 1 {
		t.Fatalf("Expected 1 usage, got %d", len(ref.Usages))
	}

	usage := ref.Usages[0]
	if usage.Type != "envFrom" {
		t.Errorf("Usage type = %q, want %q", usage.Type, "envFrom")
	}
}

func TestDetectSecrets_MixedSecrets(t *testing.T) {
	manifest := map[string]interface{}{
		"metadata": map[string]interface{}{
			"name":      "test-pod",
			"namespace": "production",
		},
		"spec": map[string]interface{}{
			"containers": []interface{}{
				map[string]interface{}{
					"name":  "app",
					"image": "nginx",
					"env": []interface{}{
						map[string]interface{}{
							"name": "DB_PASSWORD",
							"valueFrom": map[string]interface{}{
								"secretKeyRef": map[string]interface{}{
									"name": "db-creds",
									"key":  "password",
								},
							},
						},
						map[string]interface{}{
							"name": "DB_USER",
							"valueFrom": map[string]interface{}{
								"secretKeyRef": map[string]interface{}{
									"name": "db-creds",
									"key":  "username",
								},
							},
						},
					},
					"envFrom": []interface{}{
						map[string]interface{}{
							"secretRef": map[string]interface{}{
								"name": "app-config",
							},
						},
					},
				},
			},
			"volumes": []interface{}{
				map[string]interface{}{
					"name": "certs",
					"secret": map[string]interface{}{
						"secretName": "tls-secret",
					},
				},
			},
		},
	}

	refs, err := DetectSecrets(manifest)
	if err != nil {
		t.Fatalf("DetectSecrets() failed: %v", err)
	}

	if len(refs) != 3 {
		t.Fatalf("Expected 3 secret references, got %d", len(refs))
	}

	// Find each secret by name
	var dbCreds, appConfig, tlsSecret *SecretReference
	for i := range refs {
		switch refs[i].Name {
		case "db-creds":
			dbCreds = &refs[i]
		case "app-config":
			appConfig = &refs[i]
		case "tls-secret":
			tlsSecret = &refs[i]
		}
	}

	// Verify db-creds
	if dbCreds == nil {
		t.Fatal("db-creds secret not found")
		return
	}
	if len(dbCreds.Keys) != 2 {
		t.Errorf("db-creds: expected 2 keys, got %d", len(dbCreds.Keys))
	}
	if len(dbCreds.Usages) != 2 {
		t.Errorf("db-creds: expected 2 usages, got %d", len(dbCreds.Usages))
	}

	// Verify app-config
	if appConfig == nil {
		t.Fatal("app-config secret not found")
		return
	}
	if !appConfig.NeedsLookup {
		t.Error("app-config: NeedsLookup should be true")
	}

	// Verify tls-secret
	if tlsSecret == nil {
		t.Fatal("tls-secret secret not found")
		return
	}
	if !tlsSecret.NeedsLookup {
		t.Error("tls-secret: NeedsLookup should be true")
	}
}

func TestDetectSecrets_NoSecrets(t *testing.T) {
	manifest := map[string]interface{}{
		"metadata": map[string]interface{}{
			"name": "test-pod",
		},
		"spec": map[string]interface{}{
			"containers": []interface{}{
				map[string]interface{}{
					"name":  "app",
					"image": "nginx",
				},
			},
		},
	}

	refs, err := DetectSecrets(manifest)
	if err != nil {
		t.Fatalf("DetectSecrets() failed: %v", err)
	}

	if len(refs) != 0 {
		t.Errorf("Expected 0 secret references, got %d", len(refs))
	}
}

func TestGetManifestNamespace(t *testing.T) {
	tests := []struct {
		name     string
		manifest map[string]interface{}
		want     string
	}{
		{
			name: "explicit namespace",
			manifest: map[string]interface{}{
				"metadata": map[string]interface{}{
					"namespace": "production",
				},
			},
			want: "production",
		},
		{
			name: "no namespace",
			manifest: map[string]interface{}{
				"metadata": map[string]interface{}{
					"name": "test",
				},
			},
			want: "",
		},
		{
			name:     "no metadata",
			manifest: map[string]interface{}{},
			want:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Use manifest package method instead of removed helper
			m := manifest.GetFromData(tt.manifest)
			got := m.GetNamespace()
			if got != tt.want {
				t.Errorf("GetNamespace() = %q, want %q", got, tt.want)
			}
		})
	}
}
