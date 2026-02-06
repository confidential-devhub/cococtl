package integration_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-devhub/cococtl/pkg/cluster"
	"github.com/confidential-devhub/cococtl/pkg/config"
	"github.com/confidential-devhub/cococtl/pkg/initdata"
	"github.com/confidential-devhub/cococtl/pkg/manifest"
	"github.com/confidential-devhub/cococtl/pkg/sealed"
	"github.com/confidential-devhub/cococtl/pkg/secrets"
	"github.com/confidential-devhub/cococtl/pkg/trustee"
	"github.com/pelletier/go-toml/v2"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	nodev1 "k8s.io/api/node/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
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
	initdataValue, err := initdata.Generate(cfg, nil)
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
	initdataValue, err := initdata.Generate(cfg, nil)
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
	initdataValue, err := initdata.Generate(cfg, nil)
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
	initdataValue, err := initdata.Generate(cfg, nil)
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

		initdataValue, err := initdata.Generate(cfg, nil)
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

	initdataValue, err := initdata.Generate(cfg, nil)
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

// TestWorkflow_InitDetection tests that init detection queries work without kubectl
// using fake clientset. Validates RuntimeClass detection, node IP extraction, and
// Trustee deployment checks work via client-go when kubectl is not available.
func TestWorkflow_InitDetection(t *testing.T) {
	tests := []struct {
		name      string
		setupFunc func(*testing.T) kubernetes.Interface
		testFunc  func(*testing.T, kubernetes.Interface)
	}{
		{
			name: "detect RuntimeClass without kubectl",
			setupFunc: func(t *testing.T) kubernetes.Interface {
				t.Helper()
				// Create RuntimeClass with kata-qemu handler
				rc := &nodev1.RuntimeClass{
					ObjectMeta: metav1.ObjectMeta{
						Name: "kata-qemu",
					},
					Handler: "kata-qemu",
				}
				return fake.NewSimpleClientset(rc)
			},
			testFunc: func(t *testing.T, client kubernetes.Interface) {
				t.Helper()
				ctx := context.Background()
				runtimeClass := cluster.DetectRuntimeClass(ctx, client, "kata-remote")
				if runtimeClass == "" {
					t.Error("DetectRuntimeClass returned empty string")
				}
			},
		},
		{
			name: "extract node IPs without kubectl",
			setupFunc: func(t *testing.T) kubernetes.Interface {
				t.Helper()
				// Create nodes with external and internal IPs
				node1 := &corev1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: "worker-1",
					},
					Status: corev1.NodeStatus{
						Addresses: []corev1.NodeAddress{
							{Type: corev1.NodeExternalIP, Address: "203.0.113.10"},
							{Type: corev1.NodeInternalIP, Address: "10.0.1.10"},
						},
					},
				}
				node2 := &corev1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: "worker-2",
					},
					Status: corev1.NodeStatus{
						Addresses: []corev1.NodeAddress{
							{Type: corev1.NodeExternalIP, Address: "203.0.113.20"},
							{Type: corev1.NodeInternalIP, Address: "10.0.1.20"},
						},
					},
				}
				return fake.NewSimpleClientset(node1, node2)
			},
			testFunc: func(t *testing.T, client kubernetes.Interface) {
				t.Helper()
				ctx := context.Background()
				ips, err := cluster.GetNodeIPs(ctx, client)
				if err != nil {
					t.Fatalf("GetNodeIPs failed: %v", err)
				}
				if len(ips) == 0 {
					t.Error("GetNodeIPs returned empty list")
				}
				// Verify we got external IPs
				expectedIPs := map[string]bool{
					"203.0.113.10": true,
					"203.0.113.20": true,
				}
				for _, ip := range ips {
					if !expectedIPs[ip] {
						t.Errorf("Unexpected IP: %s", ip)
					}
				}
			},
		},
		{
			name: "check Trustee deployment without kubectl",
			setupFunc: func(t *testing.T) kubernetes.Interface {
				t.Helper()
				// Create Trustee deployment with correct label (app=kbs)
				deployment := &appsv1.Deployment{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "kbs",
						Namespace: "coco-tenant",
						Labels: map[string]string{
							"app": "kbs",
						},
					},
					Spec: appsv1.DeploymentSpec{
						Selector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"app": "kbs",
							},
						},
					},
				}
				return fake.NewSimpleClientset(deployment)
			},
			testFunc: func(t *testing.T, client kubernetes.Interface) {
				t.Helper()
				ctx := context.Background()
				deployed, err := trustee.IsDeployed(ctx, client, "coco-tenant")
				if err != nil {
					t.Fatalf("IsDeployed failed: %v", err)
				}
				if !deployed {
					t.Error("IsDeployed returned false, expected true")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := tt.setupFunc(t)
			tt.testFunc(t, client)
		})
	}
}

// TestWorkflow_SecretInspection tests that secret queries work without kubectl
// using fake clientset. Validates InspectSecret and InspectSecrets work via
// client-go when kubectl is not available.
func TestWorkflow_SecretInspection(t *testing.T) {
	tests := []struct {
		name      string
		setupFunc func(*testing.T) kubernetes.Interface
		testFunc  func(*testing.T, kubernetes.Interface)
	}{
		{
			name: "inspect single secret without kubectl",
			setupFunc: func(t *testing.T) kubernetes.Interface {
				t.Helper()
				secret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "db-credentials",
						Namespace: "default",
					},
					Data: map[string][]byte{
						"username": []byte("admin"),
						"password": []byte("secret123"),
					},
					Type: corev1.SecretTypeOpaque,
				}
				return fake.NewSimpleClientset(secret)
			},
			testFunc: func(t *testing.T, client kubernetes.Interface) {
				t.Helper()
				ctx := context.Background()
				secret, err := secrets.InspectSecret(ctx, client, "db-credentials", "default")
				if err != nil {
					t.Fatalf("InspectSecret failed: %v", err)
				}
				if secret == nil {
					t.Fatal("InspectSecret returned nil")
				}
				if secret.Name != "db-credentials" {
					t.Errorf("Secret name = %q, want %q", secret.Name, "db-credentials")
				}
				if len(secret.Data) != 2 {
					t.Errorf("Secret data length = %d, want 2", len(secret.Data))
				}
			},
		},
		{
			name: "inspect multiple secrets without kubectl",
			setupFunc: func(t *testing.T) kubernetes.Interface {
				t.Helper()
				secret1 := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "api-key",
						Namespace: "default",
					},
					Data: map[string][]byte{
						"key": []byte("abc123"),
					},
					Type: corev1.SecretTypeOpaque,
				}
				secret2 := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "tls-cert",
						Namespace: "default",
					},
					Data: map[string][]byte{
						"tls.crt": []byte("cert-data"),
						"tls.key": []byte("key-data"),
					},
					Type: corev1.SecretTypeTLS,
				}
				return fake.NewSimpleClientset(secret1, secret2)
			},
			testFunc: func(t *testing.T, client kubernetes.Interface) {
				t.Helper()
				ctx := context.Background()
				refs := []secrets.SecretReference{
					{Name: "api-key", Namespace: "default", NeedsLookup: true},
					{Name: "tls-cert", Namespace: "default", NeedsLookup: true},
				}
				secretMap, err := secrets.InspectSecrets(ctx, client, refs)
				if err != nil {
					t.Fatalf("InspectSecrets failed: %v", err)
				}
				if len(secretMap) != 2 {
					t.Errorf("InspectSecrets returned %d secrets, want 2", len(secretMap))
				}
				if secretMap["api-key"] == nil {
					t.Error("api-key secret not found in result")
				}
				if secretMap["tls-cert"] == nil {
					t.Error("tls-cert secret not found in result")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := tt.setupFunc(t)
			tt.testFunc(t, client)
		})
	}
}

// TestWorkflow_TrusteeQueries tests that Trustee pod and deployment queries work
// without kubectl using fake clientset. Validates IsDeployed and GetKBSPodName
// work via client-go when kubectl is not available.
func TestWorkflow_TrusteeQueries(t *testing.T) {
	tests := []struct {
		name      string
		setupFunc func(*testing.T) kubernetes.Interface
		testFunc  func(*testing.T, kubernetes.Interface)
	}{
		{
			name: "check Trustee not deployed",
			setupFunc: func(t *testing.T) kubernetes.Interface {
				t.Helper()
				// Empty clientset - no Trustee deployed
				return fake.NewSimpleClientset()
			},
			testFunc: func(t *testing.T, client kubernetes.Interface) {
				t.Helper()
				ctx := context.Background()
				deployed, err := trustee.IsDeployed(ctx, client, "coco-tenant")
				if err != nil {
					t.Fatalf("IsDeployed failed: %v", err)
				}
				if deployed {
					t.Error("IsDeployed returned true, expected false for empty cluster")
				}
			},
		},
		{
			name: "get KBS pod name without kubectl",
			setupFunc: func(t *testing.T) kubernetes.Interface {
				t.Helper()
				pod := &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "kbs-6f8d9c7b5-xk9wz",
						Namespace: "coco-tenant",
						Labels: map[string]string{
							"app": "kbs",
						},
					},
					Status: corev1.PodStatus{
						Phase: corev1.PodRunning,
					},
				}
				return fake.NewSimpleClientset(pod)
			},
			testFunc: func(t *testing.T, client kubernetes.Interface) {
				t.Helper()
				ctx := context.Background()
				podName, err := trustee.GetKBSPodName(ctx, client, "coco-tenant")
				if err != nil {
					t.Fatalf("GetKBSPodName failed: %v", err)
				}
				if podName != "kbs-6f8d9c7b5-xk9wz" {
					t.Errorf("GetKBSPodName = %q, want %q", podName, "kbs-6f8d9c7b5-xk9wz")
				}
			},
		},
		{
			name: "Trustee deployed with multiple components",
			setupFunc: func(t *testing.T) kubernetes.Interface {
				t.Helper()
				// Create KBS deployment
				kbsDeployment := &appsv1.Deployment{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "kbs",
						Namespace: "coco-tenant",
						Labels: map[string]string{
							"app": "kbs",
						},
					},
					Spec: appsv1.DeploymentSpec{
						Selector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"app": "kbs",
							},
						},
					},
				}
				// Create Trustee operator deployment
				operatorDeployment := &appsv1.Deployment{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "trustee-operator",
						Namespace: "coco-tenant",
						Labels: map[string]string{
							"app": "trustee-operator",
						},
					},
					Spec: appsv1.DeploymentSpec{
						Selector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"app": "trustee-operator",
							},
						},
					},
				}
				// Create KBS pod
				kbsPod := &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "kbs-7d9f8c6b4-mnp2q",
						Namespace: "coco-tenant",
						Labels: map[string]string{
							"app": "kbs",
						},
					},
					Status: corev1.PodStatus{
						Phase: corev1.PodRunning,
					},
				}
				return fake.NewSimpleClientset(kbsDeployment, operatorDeployment, kbsPod)
			},
			testFunc: func(t *testing.T, client kubernetes.Interface) {
				t.Helper()
				ctx := context.Background()

				// Verify Trustee is deployed
				deployed, err := trustee.IsDeployed(ctx, client, "coco-tenant")
				if err != nil {
					t.Fatalf("IsDeployed failed: %v", err)
				}
				if !deployed {
					t.Error("IsDeployed returned false, expected true")
				}

				// Verify we can get KBS pod name
				podName, err := trustee.GetKBSPodName(ctx, client, "coco-tenant")
				if err != nil {
					t.Fatalf("GetKBSPodName failed: %v", err)
				}
				if podName != "kbs-7d9f8c6b4-mnp2q" {
					t.Errorf("GetKBSPodName = %q, want %q", podName, "kbs-7d9f8c6b4-mnp2q")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := tt.setupFunc(t)
			tt.testFunc(t, client)
		})
	}
}
