package k8s

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
)

// createTestKubeconfig creates a temporary kubeconfig file for testing.
// Returns the path to the created file.
func createTestKubeconfig(t *testing.T, namespace string) string {
	t.Helper()

	template := `apiVersion: v1
kind: Config
current-context: test-context
contexts:
- name: test-context
  context:
    cluster: test-cluster
`

	// Add namespace if provided
	if namespace != "" {
		template += "    namespace: " + namespace + "\n"
	}

	template += `clusters:
- name: test-cluster
  cluster:
    server: https://localhost:6443
users:
- name: test-user
  user:
    token: fake-token
`

	dir := t.TempDir()
	path := filepath.Join(dir, "config")

	if err := os.WriteFile(path, []byte(template), 0600); err != nil {
		t.Fatalf("failed to write test kubeconfig: %v", err)
	}

	return path
}

func TestNewClient_WithMockKubeconfig(t *testing.T) {
	// Create temporary kubeconfig with namespace "test-namespace"
	kubeconfigPath := createTestKubeconfig(t, "test-namespace")

	client, err := NewClient(ClientOptions{
		Kubeconfig: kubeconfigPath,
	})

	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	if client == nil {
		t.Fatal("NewClient returned nil client")
	}

	if client.Namespace != "test-namespace" {
		t.Errorf("expected namespace 'test-namespace', got '%s'", client.Namespace)
	}

	if client.Clientset == nil {
		t.Error("Clientset is nil")
	}

	if client.Config == nil {
		t.Error("Config is nil")
	}
}

func TestNewClient_WithExplicitNamespace(t *testing.T) {
	// Create kubeconfig with context namespace "from-context"
	kubeconfigPath := createTestKubeconfig(t, "from-context")

	client, err := NewClient(ClientOptions{
		Kubeconfig: kubeconfigPath,
		Namespace:  "explicit-ns",
	})

	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	// Explicit namespace should override context namespace
	if client.Namespace != "explicit-ns" {
		t.Errorf("expected namespace 'explicit-ns', got '%s'", client.Namespace)
	}
}

func TestNewClient_DefaultNamespace(t *testing.T) {
	// Create kubeconfig with no namespace in context
	kubeconfigPath := createTestKubeconfig(t, "")

	client, err := NewClient(ClientOptions{
		Kubeconfig: kubeconfigPath,
	})

	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	// Should fall back to "default"
	if client.Namespace != "default" {
		t.Errorf("expected namespace 'default', got '%s'", client.Namespace)
	}
}

func TestNewClient_WithTimeout(t *testing.T) {
	kubeconfigPath := createTestKubeconfig(t, "test-ns")

	client, err := NewClient(ClientOptions{
		Kubeconfig: kubeconfigPath,
		Timeout:    30 * time.Second,
	})

	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	if client.Config.Timeout != 30*time.Second {
		t.Errorf("expected timeout 30s, got %v", client.Config.Timeout)
	}
}

func TestGetCurrentNamespace_FromContext(t *testing.T) {
	// Create kubeconfig with namespace
	kubeconfigPath := createTestKubeconfig(t, "test-ns")

	// Save and restore original KUBECONFIG
	origKubeconfig := os.Getenv("KUBECONFIG")
	t.Setenv("KUBECONFIG", kubeconfigPath)
	defer os.Setenv("KUBECONFIG", origKubeconfig)

	namespace, err := GetCurrentNamespace()
	if err != nil {
		t.Fatalf("GetCurrentNamespace failed: %v", err)
	}

	if namespace != "test-ns" {
		t.Errorf("expected namespace 'test-ns', got '%s'", namespace)
	}
}

func TestGetCurrentNamespace_Default(t *testing.T) {
	// Create kubeconfig without namespace
	kubeconfigPath := createTestKubeconfig(t, "")

	// Save and restore original KUBECONFIG
	origKubeconfig := os.Getenv("KUBECONFIG")
	t.Setenv("KUBECONFIG", kubeconfigPath)
	defer os.Setenv("KUBECONFIG", origKubeconfig)

	namespace, err := GetCurrentNamespace()
	if err != nil {
		t.Fatalf("GetCurrentNamespace failed: %v", err)
	}

	if namespace != "default" {
		t.Errorf("expected namespace 'default', got '%s'", namespace)
	}
}

func TestWrapError_NotFound(t *testing.T) {
	// Create a real NotFound error
	notFoundErr := apierrors.NewNotFound(
		schema.GroupResource{Group: "", Resource: "pods"},
		"test-pod",
	)

	wrapped := WrapError(notFoundErr, "get", "pod/test-pod", "test-ns")

	if wrapped == nil {
		t.Fatal("WrapError returned nil for NotFound error")
	}

	expectedMsg := "pod/test-pod not found in namespace test-ns"
	if wrapped.Error() != expectedMsg {
		t.Errorf("expected '%s', got '%s'", expectedMsg, wrapped.Error())
	}
}

func TestWrapError_NotFoundNoNamespace(t *testing.T) {
	notFoundErr := apierrors.NewNotFound(
		schema.GroupResource{Group: "", Resource: "pods"},
		"test-pod",
	)

	wrapped := WrapError(notFoundErr, "get", "pod/test-pod", "")

	expectedMsg := "pod/test-pod not found"
	if wrapped.Error() != expectedMsg {
		t.Errorf("expected '%s', got '%s'", expectedMsg, wrapped.Error())
	}
}

func TestWrapError_Forbidden(t *testing.T) {
	forbiddenErr := apierrors.NewForbidden(
		schema.GroupResource{Group: "", Resource: "secrets"},
		"my-secret",
		nil,
	)

	wrapped := WrapError(forbiddenErr, "get", "secret/my-secret", "test-ns")

	if wrapped == nil {
		t.Fatal("WrapError returned nil for Forbidden error")
	}

	expectedMsg := "permission denied: cannot get secret/my-secret in namespace test-ns"
	if wrapped.Error() != expectedMsg {
		t.Errorf("expected '%s', got '%s'", expectedMsg, wrapped.Error())
	}
}

func TestWrapError_GenericError(t *testing.T) {
	// Create a generic timeout error
	genericErr := apierrors.NewTimeoutError("request timeout", 30)

	wrapped := WrapError(genericErr, "list", "pods", "default")

	if wrapped == nil {
		t.Fatal("WrapError returned nil for generic error")
	}

	// Should contain the operation context
	msg := wrapped.Error()
	if len(msg) == 0 {
		t.Error("wrapped error message is empty")
	}

	// Generic errors should be wrapped with context
	expected := "failed to list pods in namespace default:"
	if len(msg) < len(expected) {
		t.Errorf("expected message to start with '%s', got '%s'", expected, msg)
	}
}

func TestWrapError_Nil(t *testing.T) {
	wrapped := WrapError(nil, "get", "pod", "default")

	if wrapped != nil {
		t.Error("WrapError should return nil for nil error")
	}
}

func TestClient_WithFakeClientset(t *testing.T) {
	// Create fake clientset with pre-populated objects
	fakeClientset := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-pod",
				Namespace: "test-ns",
			},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-secret",
				Namespace: "test-ns",
			},
		},
	)

	// Create a Client struct with the fake clientset
	// This proves that kubernetes.Interface typing is correct
	client := &Client{
		Clientset: fakeClientset,
		Namespace: "test-ns",
	}

	if client.Clientset == nil {
		t.Fatal("Clientset is nil")
	}

	// Verify we can use the fake clientset
	pods, err := client.Clientset.CoreV1().Pods("test-ns").List(
		context.Background(),
		metav1.ListOptions{},
	)

	if err != nil {
		t.Fatalf("failed to list pods: %v", err)
	}

	if len(pods.Items) != 1 {
		t.Errorf("expected 1 pod, got %d", len(pods.Items))
	}

	if pods.Items[0].Name != "test-pod" {
		t.Errorf("expected pod name 'test-pod', got '%s'", pods.Items[0].Name)
	}
}

func TestClient_FakeClientset_NotFound(t *testing.T) {
	fakeClientset := fake.NewSimpleClientset()

	client := &Client{
		Clientset: fakeClientset,
		Namespace: "test-ns",
	}

	// Try to get a non-existent pod
	_, err := client.Clientset.CoreV1().Pods("test-ns").Get(
		context.Background(),
		"nonexistent",
		metav1.GetOptions{},
	)

	if err == nil {
		t.Fatal("expected error for non-existent pod")
	}

	// Verify it's a NotFound error
	if !apierrors.IsNotFound(err) {
		t.Errorf("expected NotFound error, got %T: %v", err, err)
	}

	// Test WrapError with the real NotFound error
	wrapped := WrapError(err, "get", "pod/nonexistent", "test-ns")
	expectedMsg := "pod/nonexistent not found in namespace test-ns"
	if wrapped.Error() != expectedMsg {
		t.Errorf("expected '%s', got '%s'", expectedMsg, wrapped.Error())
	}
}

func TestNewClient_InvalidKubeconfig(t *testing.T) {
	// Create an invalid kubeconfig
	dir := t.TempDir()
	invalidPath := filepath.Join(dir, "invalid-config")
	if err := os.WriteFile(invalidPath, []byte("not valid yaml: ["), 0600); err != nil {
		t.Fatalf("failed to write invalid kubeconfig: %v", err)
	}

	_, err := NewClient(ClientOptions{
		Kubeconfig: invalidPath,
	})

	if err == nil {
		t.Error("expected error for invalid kubeconfig, got nil")
	}
}

func TestNewClient_NonExistentKubeconfig(t *testing.T) {
	_, err := NewClient(ClientOptions{
		Kubeconfig: "/nonexistent/path/to/kubeconfig",
	})

	if err == nil {
		t.Error("expected error for non-existent kubeconfig, got nil")
	}
}
