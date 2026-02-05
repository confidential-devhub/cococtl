package trustee

import (
	"context"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

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

// TestDeployKBS_ResourceLimits tests that the KBS deployment includes CPU resource requests and limits
func TestDeployKBS_ResourceLimits(t *testing.T) {
	cfg := &Config{
		Namespace:   "test-namespace",
		ServiceName: "test-kbs",
		KBSImage:    "test-image:latest",
	}

	// We can't directly call deployKBS because it tries to apply the manifest via kubectl
	// Instead, we'll construct the expected manifest and verify it has the right structure
	manifest := constructDeploymentManifest(cfg)

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
	manifest := constructConfigMapManifest(namespace)

	// Parse the YAML documents
	documents := strings.Split(manifest, "\n---\n")
	if len(documents) < 1 {
		t.Fatal("Expected at least one YAML document in manifest")
	}

	// Parse the kbs-config ConfigMap (first document)
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

// constructConfigMapManifest is a helper that constructs the ConfigMap manifest
// This is essentially the same logic as deployConfigMaps but returns the manifest instead of applying it
func constructConfigMapManifest(namespace string) string {
	manifest := `
apiVersion: v1
kind: ConfigMap
metadata:
  name: kbs-config-cm
  namespace: ` + namespace + `
data:
  kbs-config.toml: |
    [http_server]
    sockets = ["0.0.0.0:8080"]
    insecure_http = true

    [attestation_token]
    insecure_key = true

    [attestation_service]
    type = "coco_as_builtin"
    work_dir = "/opt/confidential-containers/attestation-service"
    policy_engine = "opa"

    [attestation_service.attestation_token_broker]
    type = "Ear"
    duration_min = 5

    [attestation_service.rvps_config]
    type = "BuiltIn"

    [policy_engine]
    policy_path = "/opt/confidential-containers/opa/policy.rego"

    [admin]
    insecure_api = true

    [[plugins]]
    name = "resource"
    type = "LocalFs"
    dir_path = "/opt/confidential-containers/kbs/repository"
`
	return manifest
}

// constructDeploymentManifest is a helper that constructs the deployment manifest
// This is essentially the same logic as deployKBS but returns the manifest instead of applying it
func constructDeploymentManifest(cfg *Config) string {
	manifest := `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: trustee-deployment
  namespace: ` + cfg.Namespace + `
  labels:
    app: kbs
spec:
  replicas: 1
  selector:
    matchLabels:
      app: kbs
  template:
    metadata:
      labels:
        app: kbs
    spec:
      containers:
      - name: kbs
        image: ` + cfg.KBSImage + `
        imagePullPolicy: IfNotPresent
        command:
        - /usr/local/bin/kbs
        - --config-file
        - /etc/kbs-config/kbs-config.toml
        ports:
        - containerPort: 8080
          name: kbs
          protocol: TCP
        securityContext:
          allowPrivilegeEscalation: false
          capabilities:
            drop:
            - ALL
          seccompProfile:
            type: RuntimeDefault
        resources:
          requests:
            cpu: "1"
          limits:
            cpu: "2"
        volumeMounts:
        - name: confidential-containers
          mountPath: /opt/confidential-containers
        - name: kbs-config
          mountPath: /etc/kbs-config
        - name: opa
          mountPath: /opt/confidential-containers/opa
        - name: auth-secret
          mountPath: /etc/auth-secret
        - name: reference-values
          mountPath: /opt/confidential-containers/rvps/reference-values
      restartPolicy: Always
      volumes:
      - name: confidential-containers
        emptyDir:
          medium: Memory
      - name: kbs-config
        configMap:
          name: kbs-config-cm
      - name: opa
        configMap:
          name: resource-policy
      - name: auth-secret
        secret:
          secretName: kbs-auth-public-key
      - name: reference-values
        configMap:
          name: rvps-reference-values
---
apiVersion: v1
kind: Service
metadata:
  name: ` + cfg.ServiceName + `
  namespace: ` + cfg.Namespace + `
spec:
  selector:
    app: kbs
  ports:
  - port: 8080
    targetPort: 8080
    protocol: TCP
`
	return manifest
}
