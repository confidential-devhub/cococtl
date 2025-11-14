package trustee

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	trusteeLabel = "app=kbs"
)

// Config holds Trustee deployment configuration
type Config struct {
	Namespace   string
	ServiceName string
	KBSImage    string
	PCCSURL     string
	Secrets     []SecretResource
}

// SecretResource represents a secret to be stored in KBS
type SecretResource struct {
	URI  string
	Path string
	Data []byte
}

// IsDeployed checks if Trustee is already running in the namespace
func IsDeployed(namespace string) (bool, error) {
	cmd := exec.Command("kubectl", "get", "deployment", "-n", namespace, "-l", trusteeLabel, "-o", "json")
	output, err := cmd.CombinedOutput()
	if err != nil {
		if strings.Contains(string(output), "NotFound") || strings.Contains(string(output), "No resources found") {
			return false, nil
		}
		return false, fmt.Errorf("failed to check Trustee deployment: %w\n%s", err, output)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(output, &result); err != nil {
		return false, fmt.Errorf("failed to parse kubectl output: %w", err)
	}

	items, ok := result["items"].([]interface{})
	if !ok || len(items) == 0 {
		return false, nil
	}

	return true, nil
}

// Deploy deploys Trustee all-in-one KBS to the specified namespace
func Deploy(cfg *Config) error {
	if err := ensureNamespace(cfg.Namespace); err != nil {
		return fmt.Errorf("failed to create namespace: %w", err)
	}

	if err := createAuthSecretFromKeys(cfg.Namespace); err != nil {
		return fmt.Errorf("failed to create auth secret: %w", err)
	}

	if err := deployConfigMaps(cfg.Namespace); err != nil {
		return fmt.Errorf("failed to deploy ConfigMaps: %w", err)
	}

	// Deploy PCCS ConfigMap if PCCSURL is configured
	if cfg.PCCSURL != "" {
		if err := deployPCCSConfigMap(cfg.Namespace, cfg.PCCSURL); err != nil {
			return fmt.Errorf("failed to deploy PCCS ConfigMap: %w", err)
		}
	}

	if err := deployKBS(cfg); err != nil {
		return fmt.Errorf("failed to deploy KBS: %w", err)
	}

	if len(cfg.Secrets) > 0 {
		if err := populateSecrets(cfg.Namespace, cfg.Secrets); err != nil {
			return fmt.Errorf("failed to populate secrets: %w", err)
		}
	}

	return nil
}

// GetServiceURL returns the URL of the deployed Trustee KBS service
func GetServiceURL(namespace, serviceName string) string {
	return fmt.Sprintf("http://%s.%s.svc.cluster.local:8080", serviceName, namespace)
}

func ensureNamespace(namespace string) error {
	cmd := exec.Command("kubectl", "create", "namespace", namespace)
	output, err := cmd.CombinedOutput()
	if err != nil && !strings.Contains(string(output), "AlreadyExists") {
		return fmt.Errorf("failed to create namespace: %w\n%s", err, output)
	}
	return nil
}

func applyManifest(yaml string) error {
	cmd := exec.Command("kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(yaml)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("kubectl apply failed: %w\n%s", err, output)
	}
	return nil
}

func createAuthSecretFromKeys(namespace string) error {
	// Generate ED25519 key pair locally
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return fmt.Errorf("failed to generate key pair: %w", err)
	}

	// Encode private key to PKCS8 PEM format
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	// Encode public key to PKIX PEM format
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	// Create temporary directory for keys
	tmpDir, err := os.MkdirTemp("", "trustee-keys-*")
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// Write keys to temporary files
	privateKeyPath := filepath.Join(tmpDir, "private.key")
	publicKeyPath := filepath.Join(tmpDir, "public.pub")

	if err := os.WriteFile(privateKeyPath, privateKeyPEM, 0600); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	if err := os.WriteFile(publicKeyPath, publicKeyPEM, 0644); err != nil {
		return fmt.Errorf("failed to write public key: %w", err)
	}

	// Create secret from files
	cmd := exec.Command("kubectl", "create", "secret", "generic",
		"kbs-auth-public-key", "-n", namespace,
		fmt.Sprintf("--from-file=%s", publicKeyPath),
		fmt.Sprintf("--from-file=%s", privateKeyPath),
		"--dry-run=client", "-o", "yaml")
	secretYAML, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to create secret YAML: %w\n%s", err, secretYAML)
	}

	// Apply the secret
	return applyManifest(string(secretYAML))
}

func deployConfigMaps(namespace string) error {
	manifest := fmt.Sprintf(`
apiVersion: v1
kind: ConfigMap
metadata:
  name: kbs-config-cm
  namespace: %s
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
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: resource-policy
  namespace: %s
data:
  policy.rego: |
    package policy
    import rego.v1

    default allow = true
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: rvps-reference-values
  namespace: %s
data:
  reference-values.json: |
    {}
`, namespace, namespace, namespace)

	return applyManifest(manifest)
}

func deployPCCSConfigMap(namespace, pccsURL string) error {
	qcnlConfig := fmt.Sprintf(`{"collateral_service":"%s"}`, pccsURL)

	manifest := fmt.Sprintf(`
apiVersion: v1
kind: ConfigMap
metadata:
  name: dcap-attestation-conf
  namespace: %s
data:
  sgx_default_qcnl.conf: '%s'
`, namespace, qcnlConfig)

	return applyManifest(manifest)
}

func deployKBS(cfg *Config) error {
	// Build volumeMounts - base mounts
	volumeMounts := `        - name: confidential-containers
          mountPath: /opt/confidential-containers
        - name: kbs-config
          mountPath: /etc/kbs-config
        - name: opa
          mountPath: /opt/confidential-containers/opa
        - name: auth-secret
          mountPath: /etc/auth-secret
        - name: reference-values
          mountPath: /opt/confidential-containers/rvps/reference-values`

	// Add PCCS volumeMount if configured
	if cfg.PCCSURL != "" {
		volumeMounts += `
        - name: qplconf
          mountPath: /etc/sgx_default_qcnl.conf
          subPath: sgx_default_qcnl.conf`
	}

	// Build volumes - base volumes
	volumes := `      - name: confidential-containers
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
          name: rvps-reference-values`

	// Add PCCS volume if configured
	if cfg.PCCSURL != "" {
		volumes += `
      - name: qplconf
        configMap:
          name: dcap-attestation-conf
          items:
          - key: sgx_default_qcnl.conf
            path: sgx_default_qcnl.conf`
	}

	manifest := fmt.Sprintf(`
apiVersion: apps/v1
kind: Deployment
metadata:
  name: trustee-deployment
  namespace: %s
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
        image: %s
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
%s
      restartPolicy: Always
      volumes:
%s
---
apiVersion: v1
kind: Service
metadata:
  name: %s
  namespace: %s
spec:
  selector:
    app: kbs
  ports:
  - port: 8080
    targetPort: 8080
    protocol: TCP
`, cfg.Namespace, cfg.KBSImage, volumeMounts, volumes, cfg.ServiceName, cfg.Namespace)

	return applyManifest(manifest)
}

func populateSecrets(namespace string, secrets []SecretResource) error {
	if len(secrets) == 0 {
		return nil
	}

	cmd := exec.Command("kubectl", "get", "pod", "-n", namespace,
		"-l", "app=kbs", "-o", "jsonpath={.items[0].metadata.name}")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to get KBS pod: %w\n%s", err, output)
	}
	podName := strings.TrimSpace(string(output))

	if podName == "" {
		return fmt.Errorf("no KBS pod found in namespace %s", namespace)
	}

	cmd = exec.Command("kubectl", "wait", "--for=condition=ready", "--timeout=120s",
		"-n", namespace, fmt.Sprintf("pod/%s", podName))
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("pod not ready: %w\n%s", err, output)
	}

	tmpDir, err := os.MkdirTemp("", "kbs-secrets-*")
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	for _, secret := range secrets {
		resourcePath := strings.TrimPrefix(secret.URI, "kbs://")
		resourcePath = strings.TrimPrefix(resourcePath, "/")

		fullPath := filepath.Join(tmpDir, resourcePath)
		if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
			return fmt.Errorf("failed to create directory: %w", err)
		}

		if err := os.WriteFile(fullPath, secret.Data, 0644); err != nil {
			return fmt.Errorf("failed to write secret: %w", err)
		}
	}

	cmd = exec.Command("kubectl", "cp", "-n", namespace,
		tmpDir+"/.", podName+":/opt/confidential-containers/kbs/repository/")
	output, err = cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to copy secrets to KBS: %w\n%s", err, output)
	}

	return nil
}

// ParseSecretSpec parses a secret specification and reads the file
func ParseSecretSpec(spec string) (*SecretResource, error) {
	parts := strings.SplitN(spec, "::", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid secret format: %s (expected kbs://uri::path)", spec)
	}

	uri := parts[0]
	pathOrData := parts[1]

	var data []byte
	var err error

	if strings.HasPrefix(pathOrData, "base64:") {
		encoded := strings.TrimPrefix(pathOrData, "base64:")
		data, err = base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("failed to decode base64 data: %w", err)
		}
	} else {
		data, err = os.ReadFile(pathOrData)
		if err != nil {
			return nil, fmt.Errorf("failed to read secret file %s: %w", pathOrData, err)
		}
	}

	return &SecretResource{
		URI:  uri,
		Path: pathOrData,
		Data: data,
	}, nil
}

// AddK8sSecretToTrustee adds a Kubernetes secret to the Trustee KBS repository
// This is a temporary solution until proper CLI tooling is available
//
// The secret data is stored in the KBS repository with the following structure:
// /opt/confidential-containers/kbs/repository/{namespace}/{secret-name}/{key}
//
// For example, a secret named "reg-cred" with key "root" and value "password"
// in namespace "coco" will be stored at:
// /opt/confidential-containers/kbs/repository/coco/reg-cred/root
func AddK8sSecretToTrustee(trusteeNamespace, secretName, secretNamespace string) error {
	// Get the KBS pod name
	cmd := exec.Command("kubectl", "get", "pod", "-n", trusteeNamespace,
		"-l", "app=kbs", "-o", "jsonpath={.items[0].metadata.name}")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to get KBS pod: %w\n%s", err, output)
	}
	podName := strings.TrimSpace(string(output))

	if podName == "" {
		return fmt.Errorf("no KBS pod found in namespace %s", trusteeNamespace)
	}

	// Wait for pod to be ready
	cmd = exec.Command("kubectl", "wait", "--for=condition=ready", "--timeout=30s",
		"-n", trusteeNamespace, fmt.Sprintf("pod/%s", podName))
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("pod not ready: %w\n%s", err, output)
	}

	// Get the secret data from Kubernetes
	cmd = exec.Command("kubectl", "get", "secret", secretName, "-n", secretNamespace,
		"-o", "jsonpath={.data}")
	output, err = cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to get secret %s in namespace %s: %w\n%s", secretName, secretNamespace, err, output)
	}

	// Parse the secret data
	var secretData map[string]string
	if err := json.Unmarshal(output, &secretData); err != nil {
		return fmt.Errorf("failed to parse secret data: %w", err)
	}

	if len(secretData) == 0 {
		return fmt.Errorf("secret %s has no data", secretName)
	}

	// Create a temporary directory to prepare the secret files
	tmpDir, err := os.MkdirTemp("", "kbs-secret-*")
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create the directory structure: {tmpDir}/{secretNamespace}/{secretName}/
	secretDir := filepath.Join(tmpDir, secretNamespace, secretName)
	if err := os.MkdirAll(secretDir, 0755); err != nil {
		return fmt.Errorf("failed to create secret directory: %w", err)
	}

	// Write each key-value pair as a file
	for key, encodedValue := range secretData {
		// Decode the base64-encoded value
		decodedValue, err := base64.StdEncoding.DecodeString(encodedValue)
		if err != nil {
			return fmt.Errorf("failed to decode secret value for key %s: %w", key, err)
		}

		// Write the decoded value to a file
		filePath := filepath.Join(secretDir, key)
		if err := os.WriteFile(filePath, decodedValue, 0644); err != nil {
			return fmt.Errorf("failed to write secret file for key %s: %w", key, err)
		}
	}

	// Copy the entire directory structure to the KBS pod
	// The structure will be: /opt/confidential-containers/kbs/repository/{secretNamespace}/{secretName}/{key}
	srcPath := filepath.Join(tmpDir, secretNamespace) + "/."
	destPath := fmt.Sprintf("%s:/opt/confidential-containers/kbs/repository/%s/", podName, secretNamespace)

	cmd = exec.Command("kubectl", "cp", "-n", trusteeNamespace, srcPath, destPath)
	output, err = cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to copy secret to KBS pod: %w\n%s", err, output)
	}

	return nil
}
