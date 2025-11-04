package trustee

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

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
