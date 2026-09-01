package trustee

import (
	"context"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/pelletier/go-toml/v2"
	"gopkg.in/yaml.v3"
)

// TestIsDeployed_Found tests that IsDeployed returns true when a deployment with the trustee label exists
func TestIsDeployed_Found(t *testing.T) {
	// Create a fake clientset with a deployment that has the trustee label
	fakeClient := fake.NewSimpleClientset(
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "trustee-deployment",
				Namespace: "coco-tenant",
				Labels: map[string]string{
					"app": "kbs",
				},
			},
		},
	)

	ctx := context.Background()
	deployed, err := IsDeployed(ctx, fakeClient, "coco-tenant")

	if err != nil {
		t.Fatalf("IsDeployed() error = %v, want nil", err)
	}

	if !deployed {
		t.Errorf("IsDeployed() = false, want true")
	}
}

// TestIsDeployed_NotFound tests that IsDeployed returns false when no deployment exists
func TestIsDeployed_NotFound(t *testing.T) {
	// Create an empty fake clientset
	fakeClient := fake.NewSimpleClientset()

	ctx := context.Background()
	deployed, err := IsDeployed(ctx, fakeClient, "coco-tenant")

	if err != nil {
		t.Fatalf("IsDeployed() error = %v, want nil", err)
	}

	if deployed {
		t.Errorf("IsDeployed() = true, want false")
	}
}

// TestIsDeployed_WrongLabel tests that IsDeployed returns false when deployment exists but has wrong label
func TestIsDeployed_WrongLabel(t *testing.T) {
	// Create a fake clientset with a deployment that has a different label
	fakeClient := fake.NewSimpleClientset(
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "other-deployment",
				Namespace: "coco-tenant",
				Labels: map[string]string{
					"app": "other-app",
				},
			},
		},
	)

	ctx := context.Background()
	deployed, err := IsDeployed(ctx, fakeClient, "coco-tenant")

	if err != nil {
		t.Fatalf("IsDeployed() error = %v, want nil", err)
	}

	if deployed {
		t.Errorf("IsDeployed() = true, want false when deployment has wrong label")
	}
}

// TestEnsureNamespace_Exists tests that ensureNamespace returns nil when namespace already exists
func TestEnsureNamespace_Exists(t *testing.T) {
	// Create a fake clientset with the namespace already existing
	fakeClient := fake.NewSimpleClientset(
		&corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: "coco-tenant",
			},
		},
	)

	ctx := context.Background()
	err := ensureNamespace(ctx, fakeClient, "coco-tenant")

	if err != nil {
		t.Errorf("ensureNamespace() error = %v, want nil when namespace exists", err)
	}
}

// TestEnsureNamespace_Creates tests that ensureNamespace creates a new namespace
func TestEnsureNamespace_Creates(t *testing.T) {
	// Create an empty fake clientset (namespace doesn't exist yet)
	fakeClient := fake.NewSimpleClientset()

	ctx := context.Background()
	err := ensureNamespace(ctx, fakeClient, "new-ns")

	if err != nil {
		t.Errorf("ensureNamespace() error = %v, want nil when creating namespace", err)
	}

	// Verify namespace was actually created
	ns, getErr := fakeClient.CoreV1().Namespaces().Get(ctx, "new-ns", metav1.GetOptions{})
	if getErr != nil {
		t.Fatalf("expected namespace to be created, got error: %v", getErr)
	}
	if ns.Name != "new-ns" {
		t.Errorf("namespace name = %q, want %q", ns.Name, "new-ns")
	}
}

// TestDeployKBS_ResourceLimits tests that the KBS deployment includes CPU resource requests and limits
func TestDeployKBS_ResourceLimits(t *testing.T) {
	cfg := &Config{
		Namespace:   "test-namespace",
		ServiceName: "test-kbs",
		KBSImage:    "test-image:latest",
	}

	manifest := buildKBSManifest(cfg)

	// Parse the YAML to verify resource limits are present
	documents := strings.Split(manifest, "\n---\n")
	if len(documents) < 1 {
		t.Fatal("Expected at least one YAML document in manifest")
	}

	// Parse the deployment (first document)
	var deployment map[string]interface{}
	if err := yaml.Unmarshal([]byte(documents[0]), &deployment); err != nil {
		t.Fatalf("Failed to parse deployment YAML: %v", err)
	}

	// Navigate to the container resources
	spec, ok := deployment["spec"].(map[string]interface{})
	if !ok {
		t.Fatal("Deployment spec not found")
	}

	template, ok := spec["template"].(map[string]interface{})
	if !ok {
		t.Fatal("Pod template not found")
	}

	podSpec, ok := template["spec"].(map[string]interface{})
	if !ok {
		t.Fatal("Pod spec not found")
	}

	containers, ok := podSpec["containers"].([]interface{})
	if !ok || len(containers) == 0 {
		t.Fatal("Containers not found")
	}

	container, ok := containers[0].(map[string]interface{})
	if !ok {
		t.Fatal("First container not found")
	}

	resources, ok := container["resources"].(map[string]interface{})
	if !ok {
		t.Fatal("Resources not found in container spec")
	}

	// Verify requests
	requests, ok := resources["requests"].(map[string]interface{})
	if !ok {
		t.Fatal("Resource requests not found")
	}

	cpuRequest, ok := requests["cpu"].(string)
	if !ok {
		t.Fatal("CPU request not found")
	}

	if cpuRequest != "1" {
		t.Errorf("CPU request = %q, want %q", cpuRequest, "1")
	}

	// Verify limits
	limits, ok := resources["limits"].(map[string]interface{})
	if !ok {
		t.Fatal("Resource limits not found")
	}

	cpuLimit, ok := limits["cpu"].(string)
	if !ok {
		t.Fatal("CPU limit not found")
	}

	if cpuLimit != "2" {
		t.Errorf("CPU limit = %q, want %q", cpuLimit, "2")
	}
}

// TestConfigMap_SocketsConfiguration tests that the KBS ConfigMap includes sockets configuration
func TestConfigMap_SocketsConfiguration(t *testing.T) {
	namespace := "test-namespace"
	manifest := buildConfigMapsManifest(namespace, "")

	// The v0.21.0 manifest is a single ConfigMap document
	documents := strings.Split(manifest, "\n---\n")
	if len(documents) != 1 {
		t.Fatalf("Expected exactly one YAML document in manifest, got %d", len(documents))
	}

	// Parse the kbs-config ConfigMap
	var configMap map[string]interface{}
	if err := yaml.Unmarshal([]byte(documents[0]), &configMap); err != nil {
		t.Fatalf("Failed to parse ConfigMap YAML: %v", err)
	}

	// Get the data section
	data, ok := configMap["data"].(map[string]interface{})
	if !ok {
		t.Fatal("ConfigMap data not found")
	}

	// Get the kbs-config.toml content
	kbsConfig, ok := data["kbs-config.toml"].(string)
	if !ok {
		t.Fatal("kbs-config.toml not found in ConfigMap")
	}

	// Verify sockets configuration is present
	if !strings.Contains(kbsConfig, `sockets = ["0.0.0.0:8080"]`) {
		t.Errorf("kbs-config.toml missing sockets configuration.\nContent:\n%s", kbsConfig)
	}

	// Verify it's in the [http_server] section
	if !strings.Contains(kbsConfig, "[http_server]") {
		t.Error("kbs-config.toml missing [http_server] section")
	}

	// Verify the sockets line comes after [http_server]
	httpServerIndex := strings.Index(kbsConfig, "[http_server]")
	socketsIndex := strings.Index(kbsConfig, `sockets = ["0.0.0.0:8080"]`)
	if socketsIndex <= httpServerIndex {
		t.Error("sockets configuration should come after [http_server] section")
	}
}

// TestConfigMap_V021Schema asserts the generated kbs-config.toml matches the
// Trustee v0.21.0 configuration schema (shipped with CoCo v0.22.0).
func TestConfigMap_V021Schema(t *testing.T) {
	namespace := "test-namespace"
	manifest := buildConfigMapsManifest(namespace, "")

	var configMap map[string]interface{}
	if err := yaml.Unmarshal([]byte(manifest), &configMap); err != nil {
		t.Fatalf("Failed to parse ConfigMap YAML: %v", err)
	}
	data, ok := configMap["data"].(map[string]interface{})
	if !ok {
		t.Fatal("ConfigMap data not found")
	}
	kbsConfig, ok := data["kbs-config.toml"].(string)
	if !ok {
		t.Fatal("kbs-config.toml not found in ConfigMap")
	}

	// Attestation token: insecure_header_jwk replaced insecure_key in v0.21.0
	if strings.Contains(kbsConfig, "insecure_key") {
		t.Error("kbs-config.toml must not contain deprecated 'insecure_key' (renamed to 'insecure_header_jwk' in v0.21.0)")
	}
	if !strings.Contains(kbsConfig, "insecure_header_jwk = true") {
		t.Error("kbs-config.toml missing [attestation_token] insecure_header_jwk = true")
	}

	// Admin: new authorization framework with bearer JWT and regex ACL
	if strings.Contains(kbsConfig, `type = "InsecureAllowAll"`) {
		t.Error("kbs-config.toml must not use legacy [admin] type = InsecureAllowAll")
	}
	for _, want := range []string{
		`authorization_mode = "AuthenticatedAuthorization"`,
		`public_key_uri = "/kbs/kbs.pem"`,
		`role = "admin"`,
		`allowed_endpoints = "^/kbs/.+$"`,
	} {
		if !strings.Contains(kbsConfig, want) {
			t.Errorf("kbs-config.toml missing admin auth entry %q", want)
		}
	}

	// Storage: unified storage backend replaced per-plugin LocalFs config
	for _, want := range []string{
		`storage_type = "LocalFs"`,
		`dir_path = "/opt/confidential-containers/kbs/storage"`,
		`storage_backend_type = "kvstorage"`,
	} {
		if !strings.Contains(kbsConfig, want) {
			t.Errorf("kbs-config.toml missing storage backend entry %q", want)
		}
	}
	// Legacy per-plugin LocalFs config used a bare "type = ..." line; the
	// v0.21.0 schema uses "storage_type = ..." under [storage_backend].
	for _, line := range strings.Split(kbsConfig, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == `type = "LocalFs"` {
			t.Error("kbs-config.toml must not use legacy per-plugin type = LocalFs (use [storage_backend] + storage_backend_type)")
		}
	}

	// Removed in v0.21.0: policy path config, AS work_dir, RVPS reference file
	for _, gone := range []string{"policy_path", "work_dir", "rvps-reference-values", "reference-values.json"} {
		if strings.Contains(kbsConfig, gone) {
			t.Errorf("kbs-config.toml contains obsolete entry %q (removed in v0.21.0)", gone)
		}
	}
}

// TestConfigMap_PCCSVerifierConfig tests that a configured PCCS URL is wired
// into the Intel DCAP verifier's collateral service setting.
func TestConfigMap_PCCSVerifierConfig(t *testing.T) {
	manifest := buildConfigMapsManifest("test-namespace", "https://pccs.example.com/sgx/certification/v4/")

	var configMap map[string]interface{}
	if err := yaml.Unmarshal([]byte(manifest), &configMap); err != nil {
		t.Fatalf("Failed to parse ConfigMap YAML: %v", err)
	}
	data, ok := configMap["data"].(map[string]interface{})
	if !ok {
		t.Fatal("ConfigMap data not found")
	}
	kbsConfig, ok := data["kbs-config.toml"].(string)
	if !ok {
		t.Fatal("kbs-config.toml not found in ConfigMap")
	}

	if !strings.Contains(kbsConfig, `[attestation_service.verifier_config.dcap_verifier]`) {
		t.Error("kbs-config.toml missing [attestation_service.verifier_config.dcap_verifier] section for PCCS URL")
	}
	if !strings.Contains(kbsConfig, `collateral_service = "https://pccs.example.com/sgx/certification/v4/"`) {
		t.Error("kbs-config.toml missing configured collateral_service URL")
	}
}

// TestConfigMap_PCCSURLSpecialCharacters verifies that quote and backslash
// characters in a PCCS URL are escaped into a valid TOML string instead of
// breaking the generated kbs-config.toml.
func TestConfigMap_PCCSURLSpecialCharacters(t *testing.T) {
	manifest := buildConfigMapsManifest("test-namespace", `https://pccs.example.com/path"a\b`)

	var configMap map[string]interface{}
	if err := yaml.Unmarshal([]byte(manifest), &configMap); err != nil {
		t.Fatalf("Failed to parse ConfigMap YAML: %v", err)
	}
	data, ok := configMap["data"].(map[string]interface{})
	if !ok {
		t.Fatal("ConfigMap data not found")
	}
	kbsConfig, ok := data["kbs-config.toml"].(string)
	if !ok {
		t.Fatal("kbs-config.toml not found in ConfigMap")
	}

	// The generated TOML must still parse and round-trip the URL value.
	var parsed map[string]interface{}
	if err := toml.Unmarshal([]byte(kbsConfig), &parsed); err != nil {
		t.Fatalf("generated kbs-config.toml is not valid TOML: %v\n%s", err, kbsConfig)
	}
	dc, ok := parsed["attestation_service"].(map[string]interface{})
	if !ok {
		t.Fatal("attestation_service section not found in generated TOML")
	}
	vc, ok := dc["verifier_config"].(map[string]interface{})
	if !ok {
		t.Fatal("verifier_config section not found in generated TOML")
	}
	dv, ok := vc["dcap_verifier"].(map[string]interface{})
	if !ok {
		t.Fatal("dcap_verifier section not found in generated TOML")
	}
	if dv["collateral_service"] != `https://pccs.example.com/path"a\b` {
		t.Errorf("collateral_service = %q, want the original URL with quotes/backslashes preserved", dv["collateral_service"])
	}
}

// TestKBSManifest_AuthSecretMountPath tests that the KBS pod mounts the admin
// public key Secret at /kbs (so the key lands at /kbs/kbs.pem), as expected by
// the v0.21.0 admin authentication framework.
func TestKBSManifest_AuthSecretMountPath(t *testing.T) {
	cfg := &Config{
		Namespace:   "test-namespace",
		ServiceName: "test-kbs",
		KBSImage:    "test-image:latest",
	}

	manifest := buildKBSManifest(cfg)

	if strings.Contains(manifest, "/etc/auth-secret") {
		t.Error("KBS manifest must not mount the auth secret at the legacy /etc/auth-secret path")
	}
	if !strings.Contains(manifest, "mountPath: /kbs") {
		t.Error("KBS manifest missing auth secret mount at /kbs (KBS v0.21.0 reads /kbs/kbs.pem)")
	}
	// Obsolete v0.17.0-era volumes must be gone
	for _, gone := range []string{"resource-policy", "rvps-reference-values", "dcap-attestation-conf"} {
		if strings.Contains(manifest, gone) {
			t.Errorf("KBS manifest references obsolete ConfigMap/volume %q", gone)
		}
	}
}
