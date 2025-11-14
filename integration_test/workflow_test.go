package integration_test

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-devhub/cococtl/pkg/config"
	"github.com/confidential-devhub/cococtl/pkg/initdata"
	"github.com/confidential-devhub/cococtl/pkg/manifest"
	"github.com/confidential-devhub/cococtl/pkg/sealed"
	"github.com/pelletier/go-toml/v2"
)

// TestWorkflow_BasicTransformation tests the basic transformation workflow:
// Load config -> Load manifest -> Set runtime class -> Add initdata annotation -> Save
func TestWorkflow_BasicTransformation(t *testing.T) {
	// 1. Load config
	cfg, err := config.Load("testdata/configs/valid-config.toml")
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// 2. Load manifest
	m, err := manifest.Load("testdata/manifests/simple-pod.yaml")
	if err != nil {
		t.Fatalf("Failed to load manifest: %v", err)
	}

	// 3. Set runtime class
	err = m.SetRuntimeClass(cfg.RuntimeClass)
	if err != nil {
		t.Fatalf("Failed to set runtime class: %v", err)
	}

	// 4. Generate and set initdata annotation
	initdataValue, err := initdata.Generate(cfg)
	if err != nil {
		t.Fatalf("Failed to generate initdata: %v", err)
	}

	err = m.SetAnnotation("io.katacontainers.config.hypervisor.cc_init_data", initdataValue)
	if err != nil {
		t.Fatalf("Failed to set initdata annotation: %v", err)
	}

	// 5. Save transformed manifest
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "transformed-pod.yaml")
	err = m.Save(outputPath)
	if err != nil {
		t.Fatalf("Failed to save manifest: %v", err)
	}

	// 6. Verify transformation
	m2, err := manifest.Load(outputPath)
	if err != nil {
		t.Fatalf("Failed to load transformed manifest: %v", err)
	}

	if m2.GetRuntimeClass() != cfg.RuntimeClass {
		t.Errorf("Runtime class = %q, want %q", m2.GetRuntimeClass(), cfg.RuntimeClass)
	}

	if m2.GetAnnotation("io.katacontainers.config.hypervisor.cc_init_data") == "" {
		t.Error("InitData annotation not found")
	}
}

// TestWorkflow_WithInitContainer tests workflow with initContainer injection
func TestWorkflow_WithInitContainer(t *testing.T) {
	cfg, err := config.Load("testdata/configs/valid-config.toml")
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	m, err := manifest.Load("testdata/manifests/simple-pod.yaml")
	if err != nil {
		t.Fatalf("Failed to load manifest: %v", err)
	}

	// Set runtime class
	err = m.SetRuntimeClass(cfg.RuntimeClass)
	if err != nil {
		t.Fatalf("Failed to set runtime class: %v", err)
	}

	// Add initContainer from config defaults
	err = m.AddInitContainer(
		"coco-init",
		cfg.InitContainerImage,
		strings.Split(cfg.InitContainerCmd, " "),
	)
	if err != nil {
		t.Fatalf("Failed to add initContainer: %v", err)
	}

	// Generate initdata
	initdataValue, err := initdata.Generate(cfg)
	if err != nil {
		t.Fatalf("Failed to generate initdata: %v", err)
	}

	err = m.SetAnnotation("io.katacontainers.config.hypervisor.cc_init_data", initdataValue)
	if err != nil {
		t.Fatalf("Failed to set annotation: %v", err)
	}

	// Verify initContainer was added
	initContainers := m.GetInitContainers()
	if len(initContainers) != 1 {
		t.Errorf("Expected 1 initContainer, got %d", len(initContainers))
	}

	firstInit, ok := initContainers[0].(map[string]interface{})
	if !ok {
		t.Fatal("InitContainer is not a map")
	}

	if firstInit["name"] != "coco-init" {
		t.Errorf("InitContainer name = %v, want coco-init", firstInit["name"])
	}

	if firstInit["image"] != cfg.InitContainerImage {
		t.Errorf("InitContainer image = %v, want %s", firstInit["image"], cfg.InitContainerImage)
	}
}

// TestWorkflow_WithSecretDownload tests workflow with secret download via initContainer
func TestWorkflow_WithSecretDownload(t *testing.T) {
	cfg, err := config.Load("testdata/configs/valid-config.toml")
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	m, err := manifest.Load("testdata/manifests/simple-pod.yaml")
	if err != nil {
		t.Fatalf("Failed to load manifest: %v", err)
	}

	// Simulate secret download workflow
	secretURI := "kbs:///default/mysecret/key1"
	targetPath := "/mnt/secret1"

	// 1. Generate sealed secret
	sealedSecret, err := sealed.GenerateSealedSecret(secretURI)
	if err != nil {
		t.Fatalf("Failed to generate sealed secret: %v", err)
	}

	// Verify sealed secret format
	if !strings.HasPrefix(sealedSecret, "sealed.fakejwsheader.") {
		t.Errorf("Sealed secret has wrong format: %s", sealedSecret)
	}

	// 2. Add emptyDir volume for secret
	volumeName := "secret-volume"
	err = m.AddVolume(volumeName, "emptyDir", map[string]interface{}{
		"medium": "Memory",
	})
	if err != nil {
		t.Fatalf("Failed to add volume: %v", err)
	}

	// 3. Add initContainer for secret download
	cdhURL := strings.Replace(secretURI, "kbs://", cfg.TrusteeServer+"/", 1)
	downloadCmd := []string{
		"sh", "-c",
		"curl -o " + filepath.Join(targetPath, "secret") + " " + cdhURL,
	}

	err = m.AddInitContainer("secret-downloader", cfg.InitContainerImage, downloadCmd)
	if err != nil {
		t.Fatalf("Failed to add secret download initContainer: %v", err)
	}

	// 4. Add volumeMount to all containers
	err = m.AddVolumeMountToContainer("", volumeName, targetPath)
	if err != nil {
		t.Fatalf("Failed to add volumeMount: %v", err)
	}

	// 5. Verify volume and volumeMount
	spec, err := m.GetSpec()
	if err != nil {
		t.Fatalf("Failed to get spec: %v", err)
	}

	volumes, ok := spec["volumes"].([]interface{})
	if !ok || len(volumes) == 0 {
		t.Error("Volume not added to spec")
	}

	containers, ok := spec["containers"].([]interface{})
	if !ok {
		t.Fatal("Containers not found in spec")
	}

	for _, c := range containers {
		container, ok := c.(map[string]interface{})
		if !ok {
			continue
		}

		volumeMounts, ok := container["volumeMounts"].([]interface{})
		if !ok || len(volumeMounts) == 0 {
			t.Error("VolumeMount not added to container")
		}
	}
}

// TestWorkflow_WithCustomAnnotations tests workflow with custom annotations
func TestWorkflow_WithCustomAnnotations(t *testing.T) {
	cfg, err := config.Load("testdata/configs/config-with-annotations.toml")
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	m, err := manifest.Load("testdata/manifests/simple-pod.yaml")
	if err != nil {
		t.Fatalf("Failed to load manifest: %v", err)
	}

	// Set runtime class
	err = m.SetRuntimeClass(cfg.RuntimeClass)
	if err != nil {
		t.Fatalf("Failed to set runtime class: %v", err)
	}

	// Add custom annotations from config
	for key, value := range cfg.Annotations {
		if value != "" {
			err = m.SetAnnotation(key, value)
			if err != nil {
				t.Fatalf("Failed to set annotation %s: %v", key, err)
			}
		}
	}

	// Generate and set initdata
	initdataValue, err := initdata.Generate(cfg)
	if err != nil {
		t.Fatalf("Failed to generate initdata: %v", err)
	}

	err = m.SetAnnotation("io.katacontainers.config.hypervisor.cc_init_data", initdataValue)
	if err != nil {
		t.Fatalf("Failed to set initdata annotation: %v", err)
	}

	// Verify custom annotations
	timeout := m.GetAnnotation("io.katacontainers.config.runtime.create_container_timeout")
	if timeout != "120" {
		t.Errorf("Timeout annotation = %q, want %q", timeout, "120")
	}

	machineType := m.GetAnnotation("io.katacontainers.config.hypervisor.machine_type")
	if machineType != "q35" {
		t.Errorf("Machine type annotation = %q, want %q", machineType, "q35")
	}
}

// TestWorkflow_CompleteWithAllFeatures tests a complete workflow with all features enabled
func TestWorkflow_CompleteWithAllFeatures(t *testing.T) {
	cfg, err := config.Load("testdata/configs/valid-config.toml")
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	m, err := manifest.Load("testdata/manifests/pod-with-multiple-containers.yaml")
	if err != nil {
		t.Fatalf("Failed to load manifest: %v", err)
	}

	// 1. Set runtime class
	err = m.SetRuntimeClass(cfg.RuntimeClass)
	if err != nil {
		t.Fatalf("Failed to set runtime class: %v", err)
	}

	// 2. Add attestation check initContainer
	err = m.AddInitContainer(
		"attestation-check",
		cfg.InitContainerImage,
		strings.Split(cfg.InitContainerCmd, " "),
	)
	if err != nil {
		t.Fatalf("Failed to add attestation initContainer: %v", err)
	}

	// 3. Add secret download
	secretURI := "kbs:///default/db-credentials/password"
	volumeName := "secrets"

	// Add volume
	err = m.AddVolume(volumeName, "emptyDir", map[string]interface{}{
		"medium": "Memory",
	})
	if err != nil {
		t.Fatalf("Failed to add volume: %v", err)
	}

	// Add secret download initContainer
	targetPath := "/mnt/secrets"
	cdhURL := strings.Replace(secretURI, "kbs://", cfg.TrusteeServer+"/", 1)
	downloadCmd := []string{
		"sh", "-c",
		"curl -o " + filepath.Join(targetPath, "password") + " " + cdhURL,
	}

	err = m.AddInitContainer("secret-download", cfg.InitContainerImage, downloadCmd)
	if err != nil {
		t.Fatalf("Failed to add secret download initContainer: %v", err)
	}

	// Add volumeMount to all containers
	err = m.AddVolumeMountToContainer("", volumeName, targetPath)
	if err != nil {
		t.Fatalf("Failed to add volumeMount: %v", err)
	}

	// 4. Generate and add initdata annotation
	initdataValue, err := initdata.Generate(cfg)
	if err != nil {
		t.Fatalf("Failed to generate initdata: %v", err)
	}

	err = m.SetAnnotation("io.katacontainers.config.hypervisor.cc_init_data", initdataValue)
	if err != nil {
		t.Fatalf("Failed to set initdata annotation: %v", err)
	}

	// 5. Save and create backup
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "complete-pod.yaml")
	err = m.Save(outputPath)
	if err != nil {
		t.Fatalf("Failed to save manifest: %v", err)
	}

	backupPath, err := m.Backup()
	if err != nil {
		t.Fatalf("Failed to create backup: %v", err)
	}

	// 6. Verify all transformations
	m2, err := manifest.Load(outputPath)
	if err != nil {
		t.Fatalf("Failed to load transformed manifest: %v", err)
	}

	// Verify runtime class
	if m2.GetRuntimeClass() != cfg.RuntimeClass {
		t.Error("RuntimeClass not set correctly")
	}

	// Verify initContainers (should have 2: attestation-check and secret-download)
	initContainers := m2.GetInitContainers()
	if len(initContainers) != 2 {
		t.Errorf("Expected 2 initContainers, got %d", len(initContainers))
	}

	// Verify initdata annotation
	annotation := m2.GetAnnotation("io.katacontainers.config.hypervisor.cc_init_data")
	if annotation == "" {
		t.Error("InitData annotation not found")
	}

	// Verify initdata content
	decoded, err := base64.StdEncoding.DecodeString(annotation)
	if err != nil {
		t.Fatalf("Failed to decode initdata: %v", err)
	}

	gzipReader, err := gzip.NewReader(bytes.NewReader(decoded))
	if err != nil {
		t.Fatalf("Failed to create gzip reader: %v", err)
	}
	defer func() {
		if err := gzipReader.Close(); err != nil {
			t.Errorf("Failed to close gzip reader: %v", err)
		}
	}()

	decompressed, err := io.ReadAll(gzipReader)
	if err != nil {
		t.Fatalf("Failed to decompress initdata: %v", err)
	}

	var initdataContent map[string]interface{}
	err = toml.Unmarshal(decompressed, &initdataContent)
	if err != nil {
		t.Fatalf("Failed to parse initdata TOML: %v", err)
	}

	// Verify initdata has required sections
	if initdataContent["aa.toml"] == "" {
		t.Error("aa.toml missing in initdata")
	}
	if initdataContent["cdh.toml"] == "" {
		t.Error("cdh.toml missing in initdata")
	}

	// Verify backup was created
	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		t.Error("Backup file was not created")
	}
}

// TestWorkflow_MultipleManifests tests applying same config to multiple manifests
func TestWorkflow_MultipleManifests(t *testing.T) {
	cfg, err := config.Load("testdata/configs/valid-config.toml")
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	manifestPaths := []string{
		"testdata/manifests/simple-pod.yaml",
		"testdata/manifests/pod-with-annotations.yaml",
		"testdata/manifests/pod-with-initcontainers.yaml",
	}

	tmpDir := t.TempDir()

	for i, manifestPath := range manifestPaths {
		m, err := manifest.Load(manifestPath)
		if err != nil {
			t.Fatalf("Failed to load manifest %s: %v", manifestPath, err)
		}

		// Apply same transformations
		err = m.SetRuntimeClass(cfg.RuntimeClass)
		if err != nil {
			t.Fatalf("Failed to set runtime class: %v", err)
		}

		initdataValue, err := initdata.Generate(cfg)
		if err != nil {
			t.Fatalf("Failed to generate initdata: %v", err)
		}

		err = m.SetAnnotation("io.katacontainers.config.hypervisor.cc_init_data", initdataValue)
		if err != nil {
			t.Fatalf("Failed to set annotation: %v", err)
		}

		// Save transformed manifest
		outputPath := filepath.Join(tmpDir, filepath.Base(manifestPath))
		err = m.Save(outputPath)
		if err != nil {
			t.Fatalf("Failed to save manifest %d: %v", i, err)
		}

		// Verify transformation
		m2, err := manifest.Load(outputPath)
		if err != nil {
			t.Fatalf("Failed to load transformed manifest %d: %v", i, err)
		}

		if m2.GetRuntimeClass() != cfg.RuntimeClass {
			t.Errorf("Manifest %d: RuntimeClass not set correctly", i)
		}

		if m2.GetAnnotation("io.katacontainers.config.hypervisor.cc_init_data") == "" {
			t.Errorf("Manifest %d: InitData annotation not found", i)
		}
	}
}

// TestWorkflow_PreserveExisting tests that transformations preserve existing manifest content
func TestWorkflow_PreserveExisting(t *testing.T) {
	cfg, err := config.Load("testdata/configs/valid-config.toml")
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Use manifest with existing initContainers and annotations
	m, err := manifest.Load("testdata/manifests/pod-with-initcontainers.yaml")
	if err != nil {
		t.Fatalf("Failed to load manifest: %v", err)
	}

	// Get existing initContainer count
	beforeCount := len(m.GetInitContainers())

	// Apply transformations
	err = m.SetRuntimeClass(cfg.RuntimeClass)
	if err != nil {
		t.Fatalf("Failed to set runtime class: %v", err)
	}

	err = m.AddInitContainer("new-init", "busybox:latest", []string{"echo", "new"})
	if err != nil {
		t.Fatalf("Failed to add initContainer: %v", err)
	}

	initdataValue, err := initdata.Generate(cfg)
	if err != nil {
		t.Fatalf("Failed to generate initdata: %v", err)
	}

	err = m.SetAnnotation("io.katacontainers.config.hypervisor.cc_init_data", initdataValue)
	if err != nil {
		t.Fatalf("Failed to set annotation: %v", err)
	}

	// Verify existing content preserved
	afterCount := len(m.GetInitContainers())
	if afterCount != beforeCount+1 {
		t.Errorf("InitContainer count = %d, want %d (existing + new)", afterCount, beforeCount+1)
	}

	// Verify new initContainer is prepended
	initContainers := m.GetInitContainers()
	firstInit, ok := initContainers[0].(map[string]interface{})
	if !ok {
		t.Fatal("First initContainer is not a map")
	}

	if firstInit["name"] != "new-init" {
		t.Errorf("First initContainer = %v, want new-init", firstInit["name"])
	}
}
