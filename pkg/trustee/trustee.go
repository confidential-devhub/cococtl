// Package trustee handles Trustee KBS deployment and management.
package trustee

import (
	"context"
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

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	trusteeLabel = "app=kbs"

	// Default attestation status secret path and content
	// This is used by the default init container to check attestation status
	defaultAttestationStatusPath    = "/opt/confidential-containers/kbs/repository/default/attestation-status/status"
	defaultAttestationStatusContent = "success"
)

// DockerConfig represents the new .dockerconfigjson format
type DockerConfig struct {
	Auths map[string]DockerAuthEntry `json:"auths"`
}

// DockerAuthEntry represents an auth entry in the Docker config
type DockerAuthEntry struct {
	Auth  string `json:"auth,omitempty"`
	Email string `json:"email,omitempty"`
}

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
func IsDeployed(ctx context.Context, clientset kubernetes.Interface, namespace string) (bool, error) {
	// List deployments with the trustee label
	deployments, err := clientset.AppsV1().Deployments(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: trusteeLabel,
	})
	if err != nil {
		// If namespace doesn't exist or no permission, treat as not deployed
		if apierrors.IsNotFound(err) || apierrors.IsForbidden(err) {
			return false, nil
		}
		return false, fmt.Errorf("failed to check Trustee deployment: %w", err)
	}

	// Check if any deployments were found
	return len(deployments.Items) > 0, nil
}

// Deploy deploys Trustee all-in-one KBS to the specified namespace
func Deploy(ctx context.Context, clientset kubernetes.Interface, cfg *Config) error {
	if err := ensureNamespace(ctx, clientset, cfg.Namespace); err != nil {
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

	// Create default attestation status secret for init container
	if err := createDefaultAttestationStatus(cfg.Namespace); err != nil {
		return fmt.Errorf("failed to create default attestation status: %w", err)
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

func ensureNamespace(ctx context.Context, clientset kubernetes.Interface, namespace string) error {
	// Check if namespace exists by trying to access it (namespace-level permission)
	// This is more reliable than 'kubectl get namespace' which requires cluster-level permissions
	_, err := clientset.CoreV1().ServiceAccounts(namespace).List(ctx, metav1.ListOptions{Limit: 1})
	if err == nil {
		// Successfully accessed resources in namespace, so it exists
		return nil
	}

	// Check if the error indicates namespace doesn't exist
	if apierrors.IsNotFound(err) {
		// Namespace doesn't exist, try to create it with kubectl
		// (namespace creation via client-go is out of scope for this phase)
		cmd := exec.Command("kubectl", "create", "namespace", namespace)
		output, err := cmd.CombinedOutput()
		if err != nil && !strings.Contains(string(output), "AlreadyExists") {
			return fmt.Errorf("failed to create namespace: %w\n%s", err, output)
		}
		return nil
	}

	// For any other error (e.g., Forbidden when user lacks namespace creation permissions
	// but namespace exists), assume namespace exists and proceed.
	// Subsequent operations will fail appropriately if the namespace truly doesn't exist.
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
	defer func() {
		if err := os.RemoveAll(tmpDir); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to remove temp directory %s: %v\n", tmpDir, err)
		}
	}()

	// Write keys to temporary files
	privateKeyPath := filepath.Join(tmpDir, "private.key")
	publicKeyPath := filepath.Join(tmpDir, "public.pub")

	if err := os.WriteFile(privateKeyPath, privateKeyPEM, 0600); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	if err := os.WriteFile(publicKeyPath, publicKeyPEM, 0600); err != nil {
		return fmt.Errorf("failed to write public key: %w", err)
	}

	// Create secret from files
	// #nosec G204 - namespace is from function parameter (application-controlled), paths are from os.MkdirTemp
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
		// Validate and sanitize the path to prevent directory traversal
		// Source - https://stackoverflow.com/a/57534618
		// Posted by Kenny Grant, modified by community. See post 'Timeline' for change history
		// Retrieved 2025-11-14, License - CC BY-SA 4.0
		cleanPath := filepath.Clean(pathOrData)

		// For absolute paths, validate they don't escape the filesystem root
		// For relative paths, ensure they're relative to current directory
		if filepath.IsAbs(cleanPath) {
			// Absolute paths are allowed for secret files
			// but ensure path doesn't contain traversal attempts
			if strings.Contains(pathOrData, "..") {
				return nil, fmt.Errorf("invalid secret path: contains directory traversal")
			}
		} else {
			// For relative paths, ensure they resolve within current directory
			cwd, err := os.Getwd()
			if err != nil {
				return nil, fmt.Errorf("failed to get current directory: %w", err)
			}
			absPath := filepath.Join(cwd, cleanPath)
			if !strings.HasPrefix(absPath, cwd) {
				return nil, fmt.Errorf("invalid secret path: escapes current directory")
			}
			cleanPath = absPath
		}

		// #nosec G304 - Path is validated above
		data, err = os.ReadFile(cleanPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read secret file %s: %w", cleanPath, err)
		}
	}

	return &SecretResource{
		URI:  uri,
		Path: pathOrData,
		Data: data,
	}, nil
}

// GetKBSKeyName returns the KBS key name for a given secret key.
// This centralizes the logic for determining what key name will be used in KBS,
// handling both format conversions (.dockercfg -> .dockerconfigjson) and
// key name normalization (stripping leading dots).
//
// This function should be used consistently when:
// - Building KBS URIs for initdata
// - Uploading secrets to KBS
//
// Returns the final key name that will be used in the KBS repository.
func GetKBSKeyName(secretKey string) string {
	// Handle .dockercfg -> .dockerconfigjson conversion
	// Trustee only handles dockerconfigjson format, so .dockercfg secrets
	// are converted to .dockerconfigjson during upload
	if secretKey == ".dockercfg" {
		// #nosec G101 - This is a key name constant, not a hardcoded credential
		secretKey = ".dockerconfigjson"
	}

	// Strip leading "." from key name as KBS doesn't support it in URIs
	// e.g., ".dockerconfigjson" becomes "dockerconfigjson"
	return strings.TrimPrefix(secretKey, ".")
}

// ConvertDockercfgToDockerConfigJSON converts the old .dockercfg format to .dockerconfigjson format
// The .dockercfg format is: { "registry": { "auth": "...", "email": "..." } }
// The .dockerconfigjson format is: { "auths": { "registry": { "auth": "...", "email": "..." } } }
func ConvertDockercfgToDockerConfigJSON(dockercfgData []byte) ([]byte, error) {
	// Parse the old format
	var oldFormat map[string]DockerAuthEntry
	if err := json.Unmarshal(dockercfgData, &oldFormat); err != nil {
		return nil, fmt.Errorf("failed to parse .dockercfg data: %w", err)
	}

	// Convert to new format by wrapping in "auths"
	newFormat := DockerConfig{
		Auths: oldFormat,
	}

	// Marshal back to JSON
	newData, err := json.Marshal(newFormat)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal .dockerconfigjson data: %w", err)
	}

	return newData, nil
}

// AddK8sSecretToTrustee adds a Kubernetes secret to the Trustee KBS repository
// This is a temporary solution until proper CLI tooling is available
//
// The secret data is stored in the KBS repository with the following structure:
// /opt/confidential-containers/kbs/repository/{namespace}/{secret-name}/{key}
//
// Key name transformations (via GetKBSKeyName):
//   - .dockercfg secrets are converted to .dockerconfigjson format (data conversion)
//     and stored with key name "dockerconfigjson" (leading dot stripped)
//   - .dockerconfigjson secrets are stored with key name "dockerconfigjson" (leading dot stripped)
//   - Other keys with leading dots have the dot stripped for KBS URI compatibility
//
// For example, a secret named "reg-cred" with key ".dockercfg" in namespace "coco"
// will have its data converted to .dockerconfigjson format and be stored at:
// /opt/confidential-containers/kbs/repository/coco/reg-cred/dockerconfigjson
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
	// #nosec G204 - trusteeNamespace is from function parameter, podName is from kubectl get output
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
	defer func() {
		if err := os.RemoveAll(tmpDir); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to remove temp directory %s: %v\n", tmpDir, err)
		}
	}()

	// Create the directory structure: {tmpDir}/{secretNamespace}/{secretName}/
	secretDir := filepath.Join(tmpDir, secretNamespace, secretName)
	if err := os.MkdirAll(secretDir, 0750); err != nil {
		return fmt.Errorf("failed to create secret directory: %w", err)
	}

	// Write each key-value pair as a file
	for key, encodedValue := range secretData {
		// Decode the base64-encoded value
		decodedValue, err := base64.StdEncoding.DecodeString(encodedValue)
		if err != nil {
			return fmt.Errorf("failed to decode secret value for key %s: %w", key, err)
		}

		// Check if this is a .dockercfg secret and convert to .dockerconfigjson format
		// Trustee only handles dockerconfigjson format
		if key == ".dockercfg" {
			convertedValue, err := ConvertDockercfgToDockerConfigJSON(decodedValue)
			if err != nil {
				return fmt.Errorf("failed to convert .dockercfg to .dockerconfigjson: %w", err)
			}
			decodedValue = convertedValue
		}

		// Get the KBS key name using the centralized logic
		// This handles both format conversion (.dockercfg -> .dockerconfigjson)
		// and key name normalization (stripping leading dots)
		kbsKey := GetKBSKeyName(key)

		// Write the decoded value to a file
		filePath := filepath.Join(secretDir, kbsKey)
		if err := os.WriteFile(filePath, decodedValue, 0600); err != nil {
			return fmt.Errorf("failed to write secret file for key %s: %w", kbsKey, err)
		}
	}

	// Copy the entire directory structure to the KBS pod
	// The structure will be: /opt/confidential-containers/kbs/repository/{secretNamespace}/{secretName}/{key}
	srcPath := filepath.Join(tmpDir, secretNamespace) + "/."
	destPath := fmt.Sprintf("%s:/opt/confidential-containers/kbs/repository/%s/", podName, secretNamespace)

	// #nosec G204 - trusteeNamespace is from function parameter, srcPath uses os.MkdirTemp tmpDir, podName is from kubectl get
	cmd = exec.Command("kubectl", "cp", "-n", trusteeNamespace, srcPath, destPath)
	output, err = cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to copy secret to KBS pod: %w\n%s", err, output)
	}

	return nil
}

// AddImagePullSecretToTrustee adds an imagePullSecret to the Trustee KBS repository
// This is a temporary solution until proper CLI tooling is available
//
// The secret data is stored in the KBS repository with the following structure:
// /opt/confidential-containers/kbs/repository/{namespace}/{secret-name}/{key}
//
// Key name transformations are handled by AddK8sSecretToTrustee via GetKBSKeyName.
// See AddK8sSecretToTrustee documentation for details on format conversions and key naming.
//
// This function is isolated for easy removal when proper tooling is available
func AddImagePullSecretToTrustee(trusteeNamespace, secretName, secretNamespace string) error {
	// Reuse the existing AddK8sSecretToTrustee function
	// ImagePullSecrets are just regular K8s secrets, so the logic is the same
	// All key name transformations are handled consistently via GetKBSKeyName
	return AddK8sSecretToTrustee(trusteeNamespace, secretName, secretNamespace)
}

// createDefaultAttestationStatus creates a default attestation-status secret in Trustee
// This is used by the default init container command to check attestation status
func createDefaultAttestationStatus(namespace string) error {
	// Get the KBS pod name
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

	// Wait for pod to be ready
	// #nosec G204 - namespace is from function parameter, podName is from kubectl get output
	cmd = exec.Command("kubectl", "wait", "--for=condition=ready", "--timeout=120s",
		"-n", namespace, fmt.Sprintf("pod/%s", podName))
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("pod not ready: %w\n%s", err, output)
	}

	// Create the directory structure and file using kubectl exec
	// Path: /opt/confidential-containers/kbs/repository/default/attestation-status/status
	mkdirCmd := "mkdir -p /opt/confidential-containers/kbs/repository/default/attestation-status"
	// #nosec G204 - namespace is from function parameter, podName is from kubectl get, mkdirCmd is a constant string
	cmd = exec.Command("kubectl", "exec", "-n", namespace, podName, "--", "sh", "-c", mkdirCmd)
	output, err = cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to create directory in KBS pod: %w\n%s", err, output)
	}

	// Write the content to the file
	writeCmd := fmt.Sprintf("echo -n '%s' > %s", defaultAttestationStatusContent, defaultAttestationStatusPath)
	// #nosec G204 - namespace is from function parameter, podName is from kubectl get, writeCmd uses constants
	cmd = exec.Command("kubectl", "exec", "-n", namespace, podName, "--", "sh", "-c", writeCmd)
	output, err = cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to write attestation status file: %w\n%s", err, output)
	}

	return nil
}
