package integration_test

import (
	"os"
	"testing"

	"github.com/confidential-devhub/cococtl/pkg/manifest"
)

func TestManifestSet_LoadMultiDocument_PodWithService(t *testing.T) {
	manifestSet, err := manifest.LoadMultiDocument("testdata/manifests/pod-with-service.yaml")
	if err != nil {
		t.Fatalf("LoadMultiDocument() failed: %v", err)
	}

	manifests := manifestSet.GetManifests()
	if len(manifests) != 2 {
		t.Fatalf("Expected 2 manifests, got %d", len(manifests))
	}

	// Verify primary manifest is Pod
	primary := manifestSet.GetPrimaryManifest()
	if primary == nil {
		t.Fatal("GetPrimaryManifest() returned nil")
	}
	if primary.GetKind() != "Pod" {
		t.Errorf("Primary manifest kind = %q, want %q", primary.GetKind(), "Pod")
	}
	if primary.GetName() != "nginx-app" {
		t.Errorf("Primary manifest name = %q, want %q", primary.GetName(), "nginx-app")
	}

	// Verify service manifest exists
	service := manifestSet.GetServiceManifest()
	if service == nil {
		t.Fatal("GetServiceManifest() returned nil")
	}
	if service.GetKind() != "Service" {
		t.Errorf("Service manifest kind = %q, want %q", service.GetKind(), "Service")
	}
	if service.GetName() != "nginx-service" {
		t.Errorf("Service manifest name = %q, want %q", service.GetName(), "nginx-service")
	}
}

func TestManifestSet_LoadMultiDocument_DeploymentWithService(t *testing.T) {
	manifestSet, err := manifest.LoadMultiDocument("testdata/manifests/deployment-with-service.yaml")
	if err != nil {
		t.Fatalf("LoadMultiDocument() failed: %v", err)
	}

	manifests := manifestSet.GetManifests()
	if len(manifests) != 2 {
		t.Fatalf("Expected 2 manifests, got %d", len(manifests))
	}

	// Verify primary manifest is Deployment
	primary := manifestSet.GetPrimaryManifest()
	if primary == nil {
		t.Fatal("GetPrimaryManifest() returned nil")
	}
	if primary.GetKind() != "Deployment" {
		t.Errorf("Primary manifest kind = %q, want %q", primary.GetKind(), "Deployment")
	}
	if primary.GetName() != "webapp" {
		t.Errorf("Primary manifest name = %q, want %q", primary.GetName(), "webapp")
	}
}

func TestManifestSet_LoadMultiDocument_SingleDocument(t *testing.T) {
	// Load a single-document YAML
	manifestSet, err := manifest.LoadMultiDocument("testdata/manifests/simple-pod.yaml")
	if err != nil {
		t.Fatalf("LoadMultiDocument() failed: %v", err)
	}

	manifests := manifestSet.GetManifests()
	if len(manifests) != 1 {
		t.Fatalf("Expected 1 manifest, got %d", len(manifests))
	}

	primary := manifestSet.GetPrimaryManifest()
	if primary == nil {
		t.Fatal("GetPrimaryManifest() returned nil")
	}
	if primary.GetKind() != "Pod" {
		t.Errorf("Primary manifest kind = %q, want %q", primary.GetKind(), "Pod")
	}
}

func TestManifestSet_GetServiceTargetPort_NumericPort(t *testing.T) {
	manifestSet, err := manifest.LoadMultiDocument("testdata/manifests/pod-with-service.yaml")
	if err != nil {
		t.Fatalf("LoadMultiDocument() failed: %v", err)
	}

	port, err := manifestSet.GetServiceTargetPort()
	if err != nil {
		t.Fatalf("GetServiceTargetPort() failed: %v", err)
	}

	expectedPort := 8080
	if port != expectedPort {
		t.Errorf("GetServiceTargetPort() = %d, want %d", port, expectedPort)
	}
}

func TestManifestSet_GetServiceTargetPort_DeploymentWithService(t *testing.T) {
	manifestSet, err := manifest.LoadMultiDocument("testdata/manifests/deployment-with-service.yaml")
	if err != nil {
		t.Fatalf("LoadMultiDocument() failed: %v", err)
	}

	port, err := manifestSet.GetServiceTargetPort()
	if err != nil {
		t.Fatalf("GetServiceTargetPort() failed: %v", err)
	}

	expectedPort := 3000
	if port != expectedPort {
		t.Errorf("GetServiceTargetPort() = %d, want %d", port, expectedPort)
	}
}

func TestManifestSet_GetServiceTargetPort_NamedPort(t *testing.T) {
	manifestSet, err := manifest.LoadMultiDocument("testdata/manifests/service-with-named-port.yaml")
	if err != nil {
		t.Fatalf("LoadMultiDocument() failed: %v", err)
	}

	// Named ports should now be resolved by looking at container ports
	port, err := manifestSet.GetServiceTargetPort()
	if err != nil {
		t.Fatalf("GetServiceTargetPort() failed: %v", err)
	}

	expectedPort := 8080 // The "http" port in the pod spec has containerPort 8080
	if port != expectedPort {
		t.Errorf("GetServiceTargetPort() = %d, want %d (resolved from named port)", port, expectedPort)
	}
}

func TestManifestSet_GetServiceTargetPort_NoTargetPort(t *testing.T) {
	manifestSet, err := manifest.LoadMultiDocument("testdata/manifests/service-no-targetport.yaml")
	if err != nil {
		t.Fatalf("LoadMultiDocument() failed: %v", err)
	}

	// When targetPort is not specified, it should default to port value
	port, err := manifestSet.GetServiceTargetPort()
	if err != nil {
		t.Fatalf("GetServiceTargetPort() failed: %v", err)
	}

	expectedPort := 9000
	if port != expectedPort {
		t.Errorf("GetServiceTargetPort() = %d, want %d (should default to port value)", port, expectedPort)
	}
}

func TestManifestSet_GetServiceTargetPort_NoService(t *testing.T) {
	manifestSet, err := manifest.LoadMultiDocument("testdata/manifests/simple-pod.yaml")
	if err != nil {
		t.Fatalf("LoadMultiDocument() failed: %v", err)
	}

	// No service in manifest, should return 0 without error
	port, err := manifestSet.GetServiceTargetPort()
	if err != nil {
		t.Fatalf("GetServiceTargetPort() failed: %v", err)
	}

	if port != 0 {
		t.Errorf("GetServiceTargetPort() = %d, want 0 (no service present)", port)
	}
}

func TestManifestSet_GetServiceTargetPort_ConflictPort(t *testing.T) {
	manifestSet, err := manifest.LoadMultiDocument("testdata/manifests/service-with-conflict-port.yaml")
	if err != nil {
		t.Fatalf("LoadMultiDocument() failed: %v", err)
	}

	port, err := manifestSet.GetServiceTargetPort()
	if err != nil {
		t.Fatalf("GetServiceTargetPort() failed: %v", err)
	}

	// The function should extract the port successfully (8443)
	// The conflict validation happens in cmd/apply.go, not here
	expectedPort := 8443
	if port != expectedPort {
		t.Errorf("GetServiceTargetPort() = %d, want %d", port, expectedPort)
	}
}

func TestManifestSet_GetPrimaryManifest_NoWorkload(t *testing.T) {
	// Create a temporary file with only a Service (no workload)
	tmpDir := t.TempDir()
	tmpFile := tmpDir + "/service-only.yaml"
	content := `apiVersion: v1
kind: Service
metadata:
  name: test-service
spec:
  selector:
    app: test
  ports:
  - port: 80
    targetPort: 8080
`
	if err := writeFile(tmpFile, content); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	manifestSet, err := manifest.LoadMultiDocument(tmpFile)
	if err != nil {
		t.Fatalf("LoadMultiDocument() failed: %v", err)
	}

	primary := manifestSet.GetPrimaryManifest()
	if primary != nil {
		t.Error("Expected GetPrimaryManifest() to return nil for Service-only manifest")
	}
}

func TestManifestSet_LoadMultiDocument_InvalidPath(t *testing.T) {
	_, err := manifest.LoadMultiDocument("nonexistent-file.yaml")
	if err == nil {
		t.Error("Expected error for nonexistent file, got nil")
	}
}

func TestManifestSet_LoadMultiDocument_EmptyFile(t *testing.T) {
	// Create a temporary empty file
	tmpDir := t.TempDir()
	emptyFile := tmpDir + "/empty.yaml"
	err := writeFile(emptyFile, "")
	if err != nil {
		t.Fatalf("Failed to create empty file: %v", err)
	}

	_, err = manifest.LoadMultiDocument(emptyFile)
	if err == nil {
		t.Error("Expected error for empty file, got nil")
	}
}

func TestManifestSet_GetServiceTargetPort_NamedPortInDeployment(t *testing.T) {
	manifestSet, err := manifest.LoadMultiDocument("testdata/manifests/deployment-with-named-port.yaml")
	if err != nil {
		t.Fatalf("LoadMultiDocument() failed: %v", err)
	}

	// Named port "web" should resolve to 5000 from first container
	port, err := manifestSet.GetServiceTargetPort()
	if err != nil {
		t.Fatalf("GetServiceTargetPort() failed: %v", err)
	}

	expectedPort := 5000
	if port != expectedPort {
		t.Errorf("GetServiceTargetPort() = %d, want %d (resolved from named port in Deployment)", port, expectedPort)
	}
}

func TestManifestSet_GetServiceTargetPort_InvalidNamedPort(t *testing.T) {
	manifestSet, err := manifest.LoadMultiDocument("testdata/manifests/service-with-invalid-named-port.yaml")
	if err != nil {
		t.Fatalf("LoadMultiDocument() failed: %v", err)
	}

	// Named port "https" doesn't exist in pod, should return error
	port, err := manifestSet.GetServiceTargetPort()
	if err == nil {
		t.Error("Expected error for invalid named port, got nil")
	}
	if port != 0 {
		t.Errorf("Expected port = 0 for invalid named port, got %d", port)
	}
}

// Helper function to write files in tests
func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0600)
}
