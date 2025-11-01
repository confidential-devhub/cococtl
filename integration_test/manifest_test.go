package integration_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-devhub/cococtl/pkg/manifest"
)

func TestManifest_Load_ValidPod(t *testing.T) {
	m, err := manifest.Load("testdata/manifests/simple-pod.yaml")
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	if m.GetKind() != "Pod" {
		t.Errorf("GetKind() = %q, want %q", m.GetKind(), "Pod")
	}

	if m.GetName() != "test-pod" {
		t.Errorf("GetName() = %q, want %q", m.GetName(), "test-pod")
	}
}

func TestManifest_Load_InvalidYAML(t *testing.T) {
	// Create invalid YAML file
	tmpDir := t.TempDir()
	invalidPath := filepath.Join(tmpDir, "invalid.yaml")
	err := os.WriteFile(invalidPath, []byte("invalid: [unclosed"), 0644)
	if err != nil {
		t.Fatalf("Failed to create invalid YAML: %v", err)
	}

	_, err = manifest.Load(invalidPath)
	if err == nil {
		t.Error("Expected error loading invalid YAML, got nil")
	}
}

func TestManifest_SetRuntimeClass_SimplePod(t *testing.T) {
	m, err := manifest.Load("testdata/manifests/simple-pod.yaml")
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	err = m.SetRuntimeClass("kata-cc")
	if err != nil {
		t.Fatalf("SetRuntimeClass() failed: %v", err)
	}

	if m.GetRuntimeClass() != "kata-cc" {
		t.Errorf("GetRuntimeClass() = %q, want %q", m.GetRuntimeClass(), "kata-cc")
	}
}

func TestManifest_SetAnnotation_NewAnnotation(t *testing.T) {
	m, err := manifest.Load("testdata/manifests/simple-pod.yaml")
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	key := "test.annotation"
	value := "test-value"

	err = m.SetAnnotation(key, value)
	if err != nil {
		t.Fatalf("SetAnnotation() failed: %v", err)
	}

	if m.GetAnnotation(key) != value {
		t.Errorf("GetAnnotation() = %q, want %q", m.GetAnnotation(key), value)
	}
}

func TestManifest_SetAnnotation_ExistingAnnotations(t *testing.T) {
	m, err := manifest.Load("testdata/manifests/pod-with-annotations.yaml")
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// Verify existing annotation
	existing := m.GetAnnotation("existing.annotation")
	if existing != "existing-value" {
		t.Errorf("Existing annotation = %q, want %q", existing, "existing-value")
	}

	// Add new annotation
	err = m.SetAnnotation("new.annotation", "new-value")
	if err != nil {
		t.Fatalf("SetAnnotation() failed: %v", err)
	}

	// Verify both annotations exist
	if m.GetAnnotation("existing.annotation") != "existing-value" {
		t.Error("Existing annotation was lost")
	}
	if m.GetAnnotation("new.annotation") != "new-value" {
		t.Error("New annotation was not added")
	}
}

func TestManifest_AddInitContainer_NoPreviousInit(t *testing.T) {
	m, err := manifest.Load("testdata/manifests/simple-pod.yaml")
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	err = m.AddInitContainer("test-init", "busybox:latest", []string{"sh", "-c", "echo test"})
	if err != nil {
		t.Fatalf("AddInitContainer() failed: %v", err)
	}

	initContainers := m.GetInitContainers()
	if len(initContainers) != 1 {
		t.Errorf("Expected 1 initContainer, got %d", len(initContainers))
	}
}

func TestManifest_AddInitContainer_PrependToExisting(t *testing.T) {
	m, err := manifest.Load("testdata/manifests/pod-with-initcontainers.yaml")
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// Should have 1 existing initContainer
	before := m.GetInitContainers()
	if len(before) != 1 {
		t.Fatalf("Expected 1 existing initContainer, got %d", len(before))
	}

	// Add new initContainer
	err = m.AddInitContainer("new-init", "busybox:latest", []string{"sh", "-c", "echo new"})
	if err != nil {
		t.Fatalf("AddInitContainer() failed: %v", err)
	}

	// Should now have 2 initContainers
	after := m.GetInitContainers()
	if len(after) != 2 {
		t.Errorf("Expected 2 initContainers, got %d", len(after))
	}

	// New initContainer should be first (prepended)
	firstInit, ok := after[0].(map[string]interface{})
	if !ok {
		t.Fatal("First initContainer is not a map")
	}
	if firstInit["name"] != "new-init" {
		t.Errorf("First initContainer name = %v, want %q", firstInit["name"], "new-init")
	}
}

func TestManifest_AddVolume_EmptyDir(t *testing.T) {
	m, err := manifest.Load("testdata/manifests/simple-pod.yaml")
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	volumeConfig := map[string]interface{}{
		"medium": "Memory",
	}

	err = m.AddVolume("test-volume", "emptyDir", volumeConfig)
	if err != nil {
		t.Fatalf("AddVolume() failed: %v", err)
	}

	// Verify volume was added
	spec, err := m.GetSpec()
	if err != nil {
		t.Fatalf("GetSpec() failed: %v", err)
	}

	volumes, ok := spec["volumes"].([]interface{})
	if !ok {
		t.Fatal("Volumes not found in spec")
	}

	if len(volumes) != 1 {
		t.Errorf("Expected 1 volume, got %d", len(volumes))
	}
}

func TestManifest_AddVolumeMount_AllContainers(t *testing.T) {
	m, err := manifest.Load("testdata/manifests/pod-with-multiple-containers.yaml")
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// Add volume first
	err = m.AddVolume("shared-volume", "emptyDir", map[string]interface{}{})
	if err != nil {
		t.Fatalf("AddVolume() failed: %v", err)
	}

	// Add volumeMount to all containers (empty containerName)
	err = m.AddVolumeMountToContainer("", "shared-volume", "/shared")
	if err != nil {
		t.Fatalf("AddVolumeMountToContainer() failed: %v", err)
	}

	// Verify both containers have the volumeMount
	spec, err := m.GetSpec()
	if err != nil {
		t.Fatalf("GetSpec() failed: %v", err)
	}

	containers, ok := spec["containers"].([]interface{})
	if !ok {
		t.Fatal("Containers not found in spec")
	}

	if len(containers) != 2 {
		t.Fatalf("Expected 2 containers, got %d", len(containers))
	}

	for i, c := range containers {
		container, ok := c.(map[string]interface{})
		if !ok {
			t.Fatalf("Container %d is not a map", i)
		}

		volumeMounts, ok := container["volumeMounts"].([]interface{})
		if !ok {
			t.Fatalf("Container %d has no volumeMounts", i)
		}

		found := false
		for _, vm := range volumeMounts {
			volumeMount, ok := vm.(map[string]interface{})
			if ok && volumeMount["name"] == "shared-volume" {
				found = true
				break
			}
		}

		if !found {
			t.Errorf("Container %d does not have shared-volume mount", i)
		}
	}
}

func TestManifest_SaveAndBackup(t *testing.T) {
	m, err := manifest.Load("testdata/manifests/simple-pod.yaml")
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "output.yaml")

	// Save manifest
	err = m.Save(outputPath)
	if err != nil {
		t.Fatalf("Save() failed: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		t.Error("Output file was not created")
	}

	// Create backup
	backupPath, err := m.Backup()
	if err != nil {
		t.Fatalf("Backup() failed: %v", err)
	}

	// Verify backup has -coco suffix
	if !strings.HasSuffix(backupPath, "-coco.yaml") {
		t.Errorf("Backup path = %q, want suffix -coco.yaml", backupPath)
	}

	// Verify backup file exists
	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		t.Error("Backup file was not created")
	}
}

func TestManifest_GetSecretRefs(t *testing.T) {
	m, err := manifest.Load("testdata/manifests/pod-with-secrets.yaml")
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	secrets := m.GetSecretRefs()
	if len(secrets) == 0 {
		t.Fatal("Expected to find secret references, got none")
	}

	// Should find secrets in both env and volumes
	// Check that we found the expected secrets
	foundMySecret := false
	foundAnotherSecret := false
	for _, secret := range secrets {
		if secret == "my-secret" {
			foundMySecret = true
		}
		if secret == "another-secret" {
			foundAnotherSecret = true
		}
	}

	if !foundMySecret {
		t.Error("Did not find 'my-secret' in secret references")
	}
	if !foundAnotherSecret {
		t.Error("Did not find 'another-secret' in secret references")
	}
}

func TestManifest_ReplaceSecretName(t *testing.T) {
	m, err := manifest.Load("testdata/manifests/pod-with-secrets.yaml")
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// Replace secret name
	err = m.ReplaceSecretName("my-secret", "new-secret")
	if err != nil {
		t.Fatalf("ReplaceSecretName() failed: %v", err)
	}

	// Get secret refs and verify replacement
	secrets := m.GetSecretRefs()

	foundNewSecret := false
	foundOldSecret := false
	for _, secret := range secrets {
		if secret == "new-secret" {
			foundNewSecret = true
		}
		if secret == "my-secret" {
			foundOldSecret = true
		}
	}

	if !foundNewSecret {
		t.Error("New secret name 'new-secret' not found after replacement")
	}
	if foundOldSecret {
		t.Error("Old secret name 'my-secret' still exists after replacement")
	}
}

func TestManifest_CompleteTransformation(t *testing.T) {
	// Test a complete transformation workflow
	m, err := manifest.Load("testdata/manifests/simple-pod.yaml")
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// Set runtime class
	err = m.SetRuntimeClass("kata-cc")
	if err != nil {
		t.Fatalf("SetRuntimeClass() failed: %v", err)
	}

	// Add annotations
	err = m.SetAnnotation("io.katacontainers.config.hypervisor.cc_init_data", "base64encodeddata")
	if err != nil {
		t.Fatalf("SetAnnotation() failed: %v", err)
	}

	// Add initContainer
	err = m.AddInitContainer("attestation-check", "fedora:latest", []string{"curl", "http://localhost:8006/cdh/resource/default/attestation-status/status"})
	if err != nil {
		t.Fatalf("AddInitContainer() failed: %v", err)
	}

	// Add volume
	err = m.AddVolume("secrets", "emptyDir", map[string]interface{}{"medium": "Memory"})
	if err != nil {
		t.Fatalf("AddVolume() failed: %v", err)
	}

	// Add volumeMount
	err = m.AddVolumeMountToContainer("", "secrets", "/mnt/secrets")
	if err != nil {
		t.Fatalf("AddVolumeMountToContainer() failed: %v", err)
	}

	// Save and verify
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "transformed.yaml")
	err = m.Save(outputPath)
	if err != nil {
		t.Fatalf("Save() failed: %v", err)
	}

	// Load the saved manifest and verify all transformations
	m2, err := manifest.Load(outputPath)
	if err != nil {
		t.Fatalf("Failed to load transformed manifest: %v", err)
	}

	if m2.GetRuntimeClass() != "kata-cc" {
		t.Error("RuntimeClass not preserved in saved manifest")
	}

	if m2.GetAnnotation("io.katacontainers.config.hypervisor.cc_init_data") == "" {
		t.Error("Annotation not preserved in saved manifest")
	}

	if len(m2.GetInitContainers()) != 1 {
		t.Error("InitContainer not preserved in saved manifest")
	}
}
