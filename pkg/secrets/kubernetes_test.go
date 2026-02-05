package secrets

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestInspectSecret_Found(t *testing.T) {
	// Setup fake clientset with a secret
	fakeClient := fake.NewSimpleClientset(
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "my-secret",
				Namespace: "default",
			},
			Data: map[string][]byte{
				"username": []byte("admin"),
				"password": []byte("secret123"),
			},
			Type: corev1.SecretTypeOpaque,
		},
	)

	ctx := context.Background()
	secret, err := InspectSecret(ctx, fakeClient, "my-secret", "default")
	if err != nil {
		t.Fatalf("InspectSecret() error = %v", err)
	}

	// Verify secret metadata
	if secret.Name != "my-secret" {
		t.Errorf("InspectSecret() Name = %q, want %q", secret.Name, "my-secret")
	}
	if secret.Namespace != "default" {
		t.Errorf("InspectSecret() Namespace = %q, want %q", secret.Namespace, "default")
	}

	// Verify data keys exist
	if len(secret.Data) != 2 {
		t.Errorf("InspectSecret() Data has %d keys, want 2", len(secret.Data))
	}
	if _, ok := secret.Data["username"]; !ok {
		t.Error("InspectSecret() Data missing 'username' key")
	}
	if _, ok := secret.Data["password"]; !ok {
		t.Error("InspectSecret() Data missing 'password' key")
	}

	// Verify data values are decoded (not base64)
	if string(secret.Data["username"]) != "admin" {
		t.Errorf("InspectSecret() Data['username'] = %q, want %q", string(secret.Data["username"]), "admin")
	}
}

func TestInspectSecret_NotFound(t *testing.T) {
	// Setup empty fake clientset
	fakeClient := fake.NewSimpleClientset()

	ctx := context.Background()
	_, err := InspectSecret(ctx, fakeClient, "missing-secret", "default")
	if err == nil {
		t.Fatal("InspectSecret() expected error for missing secret, got nil")
	}

	// Error should mention the secret name
	if !strings.Contains(err.Error(), "missing-secret") {
		t.Errorf("InspectSecret() error = %q, want error mentioning 'missing-secret'", err.Error())
	}
}

func TestInspectSecret_WithExplicitNamespace(t *testing.T) {
	// Setup fake clientset with secret in custom namespace
	fakeClient := fake.NewSimpleClientset(
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "my-secret",
				Namespace: "custom-ns",
			},
			Data: map[string][]byte{
				"key1": []byte("value1"),
			},
		},
	)

	ctx := context.Background()
	secret, err := InspectSecret(ctx, fakeClient, "my-secret", "custom-ns")
	if err != nil {
		t.Fatalf("InspectSecret() error = %v", err)
	}

	if secret.Namespace != "custom-ns" {
		t.Errorf("InspectSecret() Namespace = %q, want %q", secret.Namespace, "custom-ns")
	}
}

func TestInspectSecret_EmptyNamespaceResolution(t *testing.T) {
	// Setup fake clientset with secret in default namespace
	// Note: fake clientset doesn't validate empty namespace (known limitation)
	// Real client would error: "an empty namespace may not be set when a resource name is provided"
	// This test verifies we resolve namespace before calling API
	fakeClient := fake.NewSimpleClientset(
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "my-secret",
				Namespace: "default",
			},
			Data: map[string][]byte{
				"key1": []byte("value1"),
			},
		},
	)

	ctx := context.Background()
	// Empty namespace should resolve to current context namespace (likely "default")
	secret, err := InspectSecret(ctx, fakeClient, "my-secret", "")
	if err != nil {
		t.Fatalf("InspectSecret() error = %v", err)
	}

	// Verify namespace was resolved (not empty)
	if secret.Namespace == "" {
		t.Error("InspectSecret() returned secret with empty namespace, expected resolved namespace")
	}
}

func TestInspectSecret_DataFieldDecoding(t *testing.T) {
	// Setup fake clientset with secret containing various data types
	fakeClient := fake.NewSimpleClientset(
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "data-secret",
				Namespace: "default",
			},
			Data: map[string][]byte{
				"text":   []byte("plain text"),
				"number": []byte("12345"),
				"json":   []byte(`{"key":"value"}`),
			},
			Type: corev1.SecretTypeOpaque,
		},
	)

	ctx := context.Background()
	secret, err := InspectSecret(ctx, fakeClient, "data-secret", "default")
	if err != nil {
		t.Fatalf("InspectSecret() error = %v", err)
	}

	// Verify all data fields are accessible as []byte (auto-decoded from base64 in etcd)
	if string(secret.Data["text"]) != "plain text" {
		t.Errorf("InspectSecret() Data['text'] = %q, want %q", string(secret.Data["text"]), "plain text")
	}
	if string(secret.Data["number"]) != "12345" {
		t.Errorf("InspectSecret() Data['number'] = %q, want %q", string(secret.Data["number"]), "12345")
	}
	if string(secret.Data["json"]) != `{"key":"value"}` {
		t.Errorf("InspectSecret() Data['json'] = %q, want %q", string(secret.Data["json"]), `{"key":"value"}`)
	}

	// Verify Data is map[string][]byte (not base64 strings)
	for key, val := range secret.Data {
		if val == nil {
			t.Errorf("InspectSecret() Data[%q] is nil, expected []byte", key)
		}
	}
}

func TestInspectSecrets_MultipleSecrets(t *testing.T) {
	// Setup fake clientset with multiple secrets
	fakeClient := fake.NewSimpleClientset(
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "secret1",
				Namespace: "default",
			},
			Data: map[string][]byte{
				"key1": []byte("value1"),
			},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "secret2",
				Namespace: "default",
			},
			Data: map[string][]byte{
				"key2": []byte("value2"),
			},
		},
	)

	ctx := context.Background()
	refs := []SecretReference{
		{Name: "secret1", Namespace: "default", NeedsLookup: true},
		{Name: "secret2", Namespace: "default", NeedsLookup: true},
	}

	secrets, err := InspectSecrets(ctx, fakeClient, refs)
	if err != nil {
		t.Fatalf("InspectSecrets() error = %v", err)
	}

	// Verify both secrets returned
	if len(secrets) != 2 {
		t.Errorf("InspectSecrets() returned %d secrets, want 2", len(secrets))
	}

	// Verify secret1
	if secret1, ok := secrets["secret1"]; !ok {
		t.Error("InspectSecrets() missing 'secret1' in results")
	} else {
		if secret1.Name != "secret1" {
			t.Errorf("InspectSecrets() secret1.Name = %q, want %q", secret1.Name, "secret1")
		}
		if _, ok := secret1.Data["key1"]; !ok {
			t.Error("InspectSecrets() secret1 missing 'key1' in Data")
		}
	}

	// Verify secret2
	if secret2, ok := secrets["secret2"]; !ok {
		t.Error("InspectSecrets() missing 'secret2' in results")
	} else {
		if secret2.Name != "secret2" {
			t.Errorf("InspectSecrets() secret2.Name = %q, want %q", secret2.Name, "secret2")
		}
		if _, ok := secret2.Data["key2"]; !ok {
			t.Error("InspectSecrets() secret2 missing 'key2' in Data")
		}
	}
}

func TestInspectSecrets_NoLookupNeeded(t *testing.T) {
	// Setup empty fake clientset (secret doesn't need to exist)
	fakeClient := fake.NewSimpleClientset()

	ctx := context.Background()
	refs := []SecretReference{
		{
			Name:        "secret1",
			Namespace:   "default",
			Keys:        []string{"key1", "key2"},
			NeedsLookup: false, // Keys already known, no lookup needed
		},
	}

	secrets, err := InspectSecrets(ctx, fakeClient, refs)
	if err != nil {
		t.Fatalf("InspectSecrets() error = %v", err)
	}

	// Verify secret returned with known keys
	if len(secrets) != 1 {
		t.Errorf("InspectSecrets() returned %d secrets, want 1", len(secrets))
	}

	secret, ok := secrets["secret1"]
	if !ok {
		t.Fatal("InspectSecrets() missing 'secret1' in results")
	}

	// Verify metadata populated
	if secret.Name != "secret1" {
		t.Errorf("InspectSecrets() secret.Name = %q, want %q", secret.Name, "secret1")
	}
	if secret.Namespace != "default" {
		t.Errorf("InspectSecrets() secret.Namespace = %q, want %q", secret.Namespace, "default")
	}

	// Verify keys are present (values will be empty)
	if len(secret.Data) != 2 {
		t.Errorf("InspectSecrets() secret.Data has %d keys, want 2", len(secret.Data))
	}
	if _, ok := secret.Data["key1"]; !ok {
		t.Error("InspectSecrets() secret missing 'key1' in Data")
	}
	if _, ok := secret.Data["key2"]; !ok {
		t.Error("InspectSecrets() secret missing 'key2' in Data")
	}
}

func TestInspectSecrets_FailFast(t *testing.T) {
	// Setup fake clientset with only one secret
	fakeClient := fake.NewSimpleClientset(
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "secret1",
				Namespace: "default",
			},
			Data: map[string][]byte{
				"key1": []byte("value1"),
			},
		},
	)

	ctx := context.Background()
	refs := []SecretReference{
		{Name: "secret1", Namespace: "default", NeedsLookup: true},
		{Name: "missing-secret", Namespace: "default", NeedsLookup: true},
		{Name: "secret3", Namespace: "default", NeedsLookup: true},
	}

	_, err := InspectSecrets(ctx, fakeClient, refs)
	if err == nil {
		t.Fatal("InspectSecrets() expected error for missing secret, got nil")
	}

	// Error should mention the missing secret (fail-fast on first error)
	if !strings.Contains(err.Error(), "missing-secret") {
		t.Errorf("InspectSecrets() error = %q, want error mentioning 'missing-secret'", err.Error())
	}
}

func TestGetServiceAccountImagePullSecrets_Found(t *testing.T) {
	// Setup fake clientset with serviceaccount that has imagePullSecrets
	fakeClient := fake.NewSimpleClientset(
		&corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-sa",
				Namespace: "default",
			},
			ImagePullSecrets: []corev1.LocalObjectReference{
				{Name: "regcred"},
				{Name: "regcred2"},
			},
		},
	)

	ctx := context.Background()
	secretName, err := GetServiceAccountImagePullSecrets(ctx, fakeClient, "test-sa", "default")
	if err != nil {
		t.Fatalf("GetServiceAccountImagePullSecrets() error = %v, want nil", err)
	}

	// Should return first imagePullSecret name
	expectedName := "regcred"
	if secretName != expectedName {
		t.Errorf("GetServiceAccountImagePullSecrets() = %q, want %q", secretName, expectedName)
	}
}

func TestGetServiceAccountImagePullSecrets_NotFound(t *testing.T) {
	// Empty fake clientset - serviceaccount doesn't exist
	fakeClient := fake.NewSimpleClientset()

	ctx := context.Background()
	_, err := GetServiceAccountImagePullSecrets(ctx, fakeClient, "missing-sa", "default")
	if err == nil {
		t.Fatal("GetServiceAccountImagePullSecrets() expected error for missing serviceaccount, got nil")
	}

	// Error should mention the serviceaccount name
	if !strings.Contains(err.Error(), "missing-sa") && !strings.Contains(err.Error(), "not found") {
		t.Errorf("GetServiceAccountImagePullSecrets() error = %q, want error mentioning 'missing-sa' or 'not found'", err.Error())
	}
}

func TestGetServiceAccountImagePullSecrets_NoSecrets(t *testing.T) {
	// Setup fake clientset with serviceaccount but no imagePullSecrets
	fakeClient := fake.NewSimpleClientset(
		&corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-sa",
				Namespace: "default",
			},
			ImagePullSecrets: []corev1.LocalObjectReference{},
		},
	)

	ctx := context.Background()
	secretName, err := GetServiceAccountImagePullSecrets(ctx, fakeClient, "test-sa", "default")
	if err != nil {
		t.Fatalf("GetServiceAccountImagePullSecrets() error = %v, want nil", err)
	}

	// Should return empty string when no imagePullSecrets configured
	if secretName != "" {
		t.Errorf("GetServiceAccountImagePullSecrets() = %q, want empty string", secretName)
	}
}

func TestGetServiceAccountImagePullSecrets_EmptyNamespace(t *testing.T) {
	// Setup fake clientset with serviceaccount in default namespace
	// Note: fake clientset doesn't validate empty namespace (known limitation)
	// Real client would error: "an empty namespace may not be set when a resource name is provided"
	// This test verifies we resolve namespace before calling API
	fakeClient := fake.NewSimpleClientset(
		&corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-sa",
				Namespace: "default",
			},
			ImagePullSecrets: []corev1.LocalObjectReference{
				{Name: "regcred"},
			},
		},
	)

	ctx := context.Background()
	// Empty namespace should resolve to current context namespace
	secretName, err := GetServiceAccountImagePullSecrets(ctx, fakeClient, "test-sa", "")
	if err != nil {
		t.Fatalf("GetServiceAccountImagePullSecrets() error = %v, want nil", err)
	}

	// Should still return the secret name
	expectedName := "regcred"
	if secretName != expectedName {
		t.Errorf("GetServiceAccountImagePullSecrets() = %q, want %q", secretName, expectedName)
	}
}
