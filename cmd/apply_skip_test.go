package cmd

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-devhub/cococtl/pkg/k8s"
	"github.com/confidential-devhub/cococtl/pkg/secrets"
	"github.com/confidential-devhub/cococtl/pkg/sidecar/certs"
	"gopkg.in/yaml.v3"
)

// TestSkipApply_NamespaceResolution_Flag tests that the --namespace flag takes
// highest priority in resolveNamespace() and validates conflict detection.
func TestSkipApply_NamespaceResolution_Flag(t *testing.T) {
	t.Run("flag value returned when only flag is set", func(t *testing.T) {
		ns, err := resolveNamespace("my-namespace", "")
		if err != nil {
			t.Fatalf("resolveNamespace returned unexpected error: %v", err)
		}
		if ns != "my-namespace" {
			t.Errorf("resolveNamespace() = %q, want %q", ns, "my-namespace")
		}
	})

	t.Run("flag value returned when flag matches manifest", func(t *testing.T) {
		ns, err := resolveNamespace("production", "production")
		if err != nil {
			t.Fatalf("resolveNamespace returned unexpected error: %v", err)
		}
		if ns != "production" {
			t.Errorf("resolveNamespace() = %q, want %q", ns, "production")
		}
	})

	t.Run("error when flag and manifest namespace conflict", func(t *testing.T) {
		_, err := resolveNamespace("flag-ns", "manifest-ns")
		if err == nil {
			t.Fatal("resolveNamespace should return error when flag and manifest namespace conflict")
		}
		if !strings.Contains(err.Error(), "does not match") {
			t.Errorf("error message should contain 'does not match', got: %v", err)
		}
	})

	t.Run("error message includes both namespaces", func(t *testing.T) {
		_, err := resolveNamespace("alpha", "beta")
		if err == nil {
			t.Fatal("resolveNamespace should return error for conflicting namespaces")
		}
		errMsg := err.Error()
		if !strings.Contains(errMsg, "beta") || !strings.Contains(errMsg, "alpha") {
			t.Errorf("error message should contain both namespace values, got: %v", err)
		}
	})
}

// TestSkipApply_NamespaceResolution_ManifestOnly tests that the manifest
// metadata.namespace is used when no flag is provided.
func TestSkipApply_NamespaceResolution_ManifestOnly(t *testing.T) {
	ns, err := resolveNamespace("", "manifest-namespace")
	if err != nil {
		t.Fatalf("resolveNamespace returned unexpected error: %v", err)
	}
	if ns != "manifest-namespace" {
		t.Errorf("resolveNamespace() = %q, want %q", ns, "manifest-namespace")
	}
}

// TestSkipApply_NamespaceResolution_KubeconfigFallback tests that the namespace
// from kubeconfig context is used when no flag and no manifest namespace exist.
func TestSkipApply_NamespaceResolution_KubeconfigFallback(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a minimal valid kubeconfig with a namespace set in the context
	kubeconfigContent := `apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://localhost:6443
  name: test-cluster
contexts:
- context:
    cluster: test-cluster
    namespace: test-from-kubeconfig
  name: test-context
current-context: test-context
users:
- name: test-user
`
	kubeconfigPath := filepath.Join(tmpDir, "kubeconfig")
	if err := os.WriteFile(kubeconfigPath, []byte(kubeconfigContent), 0600); err != nil {
		t.Fatalf("Failed to write test kubeconfig: %v", err)
	}

	// Set KUBECONFIG env (t.Setenv restores original value on cleanup)
	t.Setenv("KUBECONFIG", kubeconfigPath)

	// Verify k8s.GetCurrentNamespace() returns the kubeconfig namespace
	kubeconfigNs, err := k8s.GetCurrentNamespace()
	if err != nil {
		t.Fatalf("k8s.GetCurrentNamespace() returned error: %v", err)
	}
	if kubeconfigNs != "test-from-kubeconfig" {
		t.Errorf("k8s.GetCurrentNamespace() = %q, want %q", kubeconfigNs, "test-from-kubeconfig")
	}

	// Verify resolveNamespace falls back to kubeconfig when flag and manifest are empty
	ns, err := resolveNamespace("", "")
	if err != nil {
		t.Fatalf("resolveNamespace returned unexpected error: %v", err)
	}
	if ns != "test-from-kubeconfig" {
		t.Errorf("resolveNamespace() = %q, want %q (expected kubeconfig fallback)", ns, "test-from-kubeconfig")
	}
}

// TestSkipApply_NamespaceResolution_DefaultFallback tests that "default" is
// returned when no flag, no manifest namespace, and no kubeconfig namespace exist.
func TestSkipApply_NamespaceResolution_DefaultFallback(t *testing.T) {
	// Point KUBECONFIG to a non-existent path so kubeconfig reading fails
	// (t.Setenv restores original value on cleanup)
	t.Setenv("KUBECONFIG", filepath.Join(t.TempDir(), "nonexistent-kubeconfig"))

	ns, err := resolveNamespace("", "")
	if err != nil {
		t.Fatalf("resolveNamespace returned unexpected error: %v", err)
	}
	if ns != "default" {
		t.Errorf("resolveNamespace() = %q, want %q (expected default fallback)", ns, "default")
	}
}

// TestSkipApply_SidecarCertFileSaving tests that saveSidecarCertsToYAML creates
// a properly formatted Kubernetes TLS Secret YAML file with correct permissions.
func TestSkipApply_SidecarCertFileSaving(t *testing.T) {
	// Generate a CA for signing the server cert
	ca, err := certs.GenerateCA("test-ca")
	if err != nil {
		t.Fatalf("Failed to generate CA: %v", err)
	}

	// Generate a server certificate
	sans := certs.SANs{
		DNSNames:    []string{"test-app.test-ns.svc.cluster.local"},
		IPAddresses: []string{"10.0.0.1"},
	}
	serverCert, err := certs.GenerateServerCert(ca.CertPEM, ca.KeyPEM, "test-app", sans)
	if err != nil {
		t.Fatalf("Failed to generate server cert: %v", err)
	}

	// Create a temp manifest path
	tmpDir := t.TempDir()
	manifestPath := filepath.Join(tmpDir, "app.yaml")
	// Create a placeholder manifest file (saveSidecarCertsToYAML uses the path for naming)
	if err := os.WriteFile(manifestPath, []byte("placeholder"), 0600); err != nil {
		t.Fatalf("Failed to create placeholder manifest: %v", err)
	}

	// Call saveSidecarCertsToYAML
	certFilePath, err := saveSidecarCertsToYAML(manifestPath, serverCert, "test-app", "test-ns")
	if err != nil {
		t.Fatalf("saveSidecarCertsToYAML returned error: %v", err)
	}

	// Verify the cert file path follows naming convention
	expectedPath := filepath.Join(tmpDir, "app-sidecar-certs.yaml")
	if certFilePath != expectedPath {
		t.Errorf("cert file path = %q, want %q", certFilePath, expectedPath)
	}

	// Verify file exists
	fileInfo, err := os.Stat(certFilePath)
	if err != nil {
		t.Fatalf("cert file does not exist: %v", err)
	}

	// Verify file permissions are 0600
	perm := fileInfo.Mode().Perm()
	if perm != 0600 {
		t.Errorf("cert file permissions = %o, want %o", perm, 0600)
	}

	// Read and parse the YAML file
	data, err := os.ReadFile(certFilePath)
	if err != nil {
		t.Fatalf("Failed to read cert file: %v", err)
	}

	var secret map[string]interface{}
	if err := yaml.Unmarshal(data, &secret); err != nil {
		t.Fatalf("Failed to parse cert file YAML: %v", err)
	}

	// Verify apiVersion
	if apiVersion, ok := secret["apiVersion"].(string); !ok || apiVersion != "v1" {
		t.Errorf("apiVersion = %v, want %q", secret["apiVersion"], "v1")
	}

	// Verify kind
	if kind, ok := secret["kind"].(string); !ok || kind != "Secret" {
		t.Errorf("kind = %v, want %q", secret["kind"], "Secret")
	}

	// Verify type
	if secretType, ok := secret["type"].(string); !ok || secretType != "kubernetes.io/tls" {
		t.Errorf("type = %v, want %q", secret["type"], "kubernetes.io/tls")
	}

	// Verify metadata
	metadata, ok := secret["metadata"].(map[string]interface{})
	if !ok {
		t.Fatalf("metadata is not a map: %T", secret["metadata"])
	}
	if name, ok := metadata["name"].(string); !ok || name != "sidecar-tls-test-app" {
		t.Errorf("metadata.name = %v, want %q", metadata["name"], "sidecar-tls-test-app")
	}
	if namespace, ok := metadata["namespace"].(string); !ok || namespace != "test-ns" {
		t.Errorf("metadata.namespace = %v, want %q", metadata["namespace"], "test-ns")
	}

	// Verify data fields contain base64-encoded content
	secretData, ok := secret["data"].(map[string]interface{})
	if !ok {
		t.Fatalf("data is not a map: %T", secret["data"])
	}

	tlsCrt, ok := secretData["tls.crt"].(string)
	if !ok || tlsCrt == "" {
		t.Error("data[tls.crt] is missing or empty")
	} else {
		// Verify tls.crt is valid base64
		decoded, err := base64.StdEncoding.DecodeString(tlsCrt)
		if err != nil {
			t.Errorf("data[tls.crt] is not valid base64: %v", err)
		}
		// Verify decoded content matches the original cert PEM
		if string(decoded) != string(serverCert.CertPEM) {
			t.Error("data[tls.crt] decoded content does not match original cert PEM")
		}
	}

	tlsKey, ok := secretData["tls.key"].(string)
	if !ok || tlsKey == "" {
		t.Error("data[tls.key] is missing or empty")
	} else {
		// Verify tls.key is valid base64
		decoded, err := base64.StdEncoding.DecodeString(tlsKey)
		if err != nil {
			t.Errorf("data[tls.key] is not valid base64: %v", err)
		}
		// Verify decoded content matches the original key PEM
		if string(decoded) != string(serverCert.KeyPEM) {
			t.Error("data[tls.key] decoded content does not match original key PEM")
		}
	}
}

func TestSkipApply_SecretsClusterUnreachableError_Format(t *testing.T) {
	refs := []secrets.SecretReference{
		{
			Name: "app-config",
			Usages: []secrets.SecretUsage{
				{Type: "envFrom", ContainerName: "app"},
			},
		},
		{
			Name: "volume-data",
			Usages: []secrets.SecretUsage{
				{Type: "volume", VolumeName: "data-vol"},
			},
		},
	}

	err := secretsClusterUnreachableError(refs, fmt.Errorf("connection refused"))

	errMsg := err.Error()

	// Verify error mentions secret names
	if !strings.Contains(errMsg, "app-config") {
		t.Errorf("Error should mention 'app-config', got: %s", errMsg)
	}
	if !strings.Contains(errMsg, "volume-data") {
		t.Errorf("Error should mention 'volume-data', got: %s", errMsg)
	}

	// Verify error mentions usage types
	if !strings.Contains(errMsg, "envFrom") {
		t.Errorf("Error should mention 'envFrom' usage type, got: %s", errMsg)
	}
	if !strings.Contains(errMsg, "volume") {
		t.Errorf("Error should mention 'volume' usage type, got: %s", errMsg)
	}

	// Verify actionable guidance
	if !strings.Contains(errMsg, "explicit key references") {
		t.Errorf("Error should suggest explicit key references, got: %s", errMsg)
	}
	if !strings.Contains(errMsg, "convert-secrets=false") {
		t.Errorf("Error should suggest --convert-secrets=false, got: %s", errMsg)
	}

	// Verify underlying error included
	if !strings.Contains(errMsg, "connection refused") {
		t.Errorf("Error should include underlying error, got: %s", errMsg)
	}
}

func TestSkipApply_SecretsClusterQueryError_Format(t *testing.T) {
	refs := []secrets.SecretReference{
		{Name: "missing-secret"},
	}

	err := secretsClusterQueryError(refs, fmt.Errorf("secret not found"))

	errMsg := err.Error()

	if !strings.Contains(errMsg, "missing-secret") {
		t.Errorf("Error should mention secret name, got: %s", errMsg)
	}
	if !strings.Contains(errMsg, "secret not found") {
		t.Errorf("Error should include underlying error, got: %s", errMsg)
	}
	if !strings.Contains(errMsg, "explicit key references") {
		t.Errorf("Error should suggest explicit key references, got: %s", errMsg)
	}
}

func TestSkipApply_SecretRefSplitting(t *testing.T) {
	// Simulate mixed refs
	allRefs := []secrets.SecretReference{
		{Name: "explicit-secret", NeedsLookup: false, Keys: []string{"key1"}},
		{Name: "envfrom-secret", NeedsLookup: true},
		{Name: "volume-explicit", NeedsLookup: false, Keys: []string{"cert", "key"}},
		{Name: "volume-all", NeedsLookup: true},
	}

	var offlineRefs, clusterRefs []secrets.SecretReference
	for _, ref := range allRefs {
		if ref.NeedsLookup {
			clusterRefs = append(clusterRefs, ref)
		} else {
			offlineRefs = append(offlineRefs, ref)
		}
	}

	if len(offlineRefs) != 2 {
		t.Errorf("Expected 2 offline refs, got %d", len(offlineRefs))
	}
	if len(clusterRefs) != 2 {
		t.Errorf("Expected 2 cluster refs, got %d", len(clusterRefs))
	}

	// Verify correct assignment
	if offlineRefs[0].Name != "explicit-secret" {
		t.Errorf("First offline ref should be 'explicit-secret', got %q", offlineRefs[0].Name)
	}
	if clusterRefs[0].Name != "envfrom-secret" {
		t.Errorf("First cluster ref should be 'envfrom-secret', got %q", clusterRefs[0].Name)
	}
}
