// Package trustee handles Trustee KBS deployment and management.
package trustee

import (
	"context"
	"crypto/ed25519"
	"errors"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"

	"github.com/confidential-devhub/cococtl/pkg/kbsclient"
)

const (
	trusteeLabel = "app=kbs"

	// defaultAttestationStatusContent is uploaded to KBS during deploy so the
	// init container can verify attestation succeeded.
	defaultAttestationStatusContent = "success"

	// defaultKBSPort is the port the KBS pod listens on.
	defaultKBSPort = 8080

	// kbsReadyTimeout is the maximum time Deploy waits for the KBS pod to
	// become Ready before giving up.
	kbsReadyTimeout = 2 * time.Minute

	// kbsAdminTimeout bounds the port-forward handshake and the subsequent
	// SetResource HTTP call so a network hang cannot block Deploy indefinitely.
	kbsAdminTimeout = 30 * time.Second
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

	// RESTConfig is required for port-forwarding to the KBS pod during Deploy.
	RESTConfig *rest.Config

	// AuthDir is the directory where the generated KBS admin private key is
	// persisted for later use by 'kbs populate'.  If empty, defaults to
	// ~/.kube/coco-kbs-auth (resolved via DefaultAuthDir).
	AuthDir string
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

// Deploy deploys Trustee all-in-one KBS to the specified namespace.
// cfg.RESTConfig must be set; it is used to port-forward to the KBS pod
// so that the admin HTTP API can be called without requiring an externally
// reachable service URL.
func Deploy(ctx context.Context, clientset kubernetes.Interface, cfg *Config) error {
	if cfg.RESTConfig == nil {
		return fmt.Errorf("cfg.RESTConfig is required for KBS deployment")
	}

	// Resolve the auth directory once and write it back so the caller can read
	// the concrete path without calling DefaultAuthDir themselves.
	authDir, err := DefaultAuthDir(cfg.AuthDir)
	if err != nil {
		return fmt.Errorf("failed to resolve auth directory: %w", err)
	}
	cfg.AuthDir = authDir

	if err := ensureNamespace(ctx, clientset, cfg.Namespace); err != nil {
		return fmt.Errorf("failed to create namespace: %w", err)
	}

	privateKey, err := createAuthSecretFromKeys(ctx, cfg.Namespace, authDir)
	if err != nil {
		return fmt.Errorf("failed to create auth secret: %w", err)
	}

	if err := deployConfigMaps(ctx, cfg.Namespace); err != nil {
		return fmt.Errorf("failed to deploy ConfigMaps: %w", err)
	}

	if cfg.PCCSURL != "" {
		if err := deployPCCSConfigMap(ctx, cfg.Namespace, cfg.PCCSURL); err != nil {
			return fmt.Errorf("failed to deploy PCCS ConfigMap: %w", err)
		}
	}

	if err := deployKBS(ctx, cfg); err != nil {
		return fmt.Errorf("failed to deploy KBS: %w", err)
	}

	// Wait for the KBS pod to be ready, bounded by kbsReadyTimeout.
	waitCtx, waitCancel := context.WithTimeout(ctx, kbsReadyTimeout)
	defer waitCancel()
	if err := WaitForKBSReady(waitCtx, clientset, cfg.Namespace); err != nil {
		return fmt.Errorf("KBS pod not ready: %w", err)
	}

	// Select an explicitly ready pod to port-forward to, guarding against
	// rollouts where a Terminating pod might be listed first.
	podName, err := getReadyKBSPodName(waitCtx, clientset, cfg.Namespace)
	if err != nil {
		return fmt.Errorf("failed to find ready KBS pod: %w", err)
	}

	// Both the port-forward handshake and the SetResource HTTP call share a
	// single bounded context.  30 s is sufficient for both operations together.
	adminCtx, adminCancel := context.WithTimeout(ctx, kbsAdminTimeout)
	defer adminCancel()

	localPort, stopForward, err := portForwardKBSPod(adminCtx, cfg.RESTConfig, clientset, cfg.Namespace, podName)
	if err != nil {
		return fmt.Errorf("failed to port-forward to KBS pod: %w", err)
	}
	defer stopForward()

	kbsURL := fmt.Sprintf("http://127.0.0.1:%d", localPort)
	kbsClient, err := kbsclient.New(kbsURL, privateKey, nil)
	if err != nil {
		return fmt.Errorf("failed to create KBS client: %w", err)
	}

	// Upload the default attestation status via the KBS admin HTTP API.
	// This replaces the former kubectl exec approach.
	if err := kbsClient.SetResource(adminCtx, "default/attestation-status/status", []byte(defaultAttestationStatusContent)); err != nil {
		return fmt.Errorf("failed to set default attestation status: %w", err)
	}

	if len(cfg.Secrets) > 0 {
		if err := populateSecrets(ctx, clientset, cfg.Namespace, cfg.Secrets); err != nil {
			return fmt.Errorf("failed to populate secrets: %w", err)
		}
	}

	return nil
}

// GetServiceURL returns the URL of the deployed Trustee KBS service
func GetServiceURL(namespace, serviceName string) string {
	return fmt.Sprintf("http://%s.%s.svc.cluster.local:%d", serviceName, namespace, defaultKBSPort)
}

// DefaultAuthDir returns the resolved, cleaned KBS auth directory.
// If override is empty it defaults to ~/.kube/coco-kbs-auth.
// A leading ~ in override is expanded to the user's home directory.
func DefaultAuthDir(override string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %w", err)
	}
	if override == "" {
		return filepath.Join(home, ".kube", "coco-kbs-auth"), nil
	}
	// Expand a leading ~ so callers can pass "~/custom-dir" safely.
	// TrimPrefix strips the leading "~/" leaving a relative segment that
	// filepath.Join correctly appends under home (override[1:] would leave
	// a leading "/" that silently drops the home prefix).
	if override == "~" {
		override = home
	} else if strings.HasPrefix(override, "~/") {
		override = filepath.Join(home, strings.TrimPrefix(override, "~/"))
	}
	return filepath.Clean(override), nil
}

// portForwardKBSPod opens a port-forward from a random local port to port
// defaultKBSPort on the named pod.  It returns the local port number and a
// stop function the caller must invoke when done.
func portForwardKBSPod(ctx context.Context, restConfig *rest.Config, clientset kubernetes.Interface, namespace, podName string) (localPort uint16, stop func(), err error) {
	url := clientset.CoreV1().RESTClient().Post().
		Resource("pods").
		Namespace(namespace).
		Name(podName).
		SubResource("portforward").
		URL()

	transport, upgrader, err := spdy.RoundTripperFor(restConfig)
	if err != nil {
		return 0, nil, fmt.Errorf("create port-forward transport: %w", err)
	}

	dialer := spdy.NewDialer(upgrader, &http.Client{Transport: transport}, http.MethodPost, url)

	stopCh := make(chan struct{})
	readyCh := make(chan struct{})

	fw, err := portforward.New(dialer, []string{fmt.Sprintf("0:%d", defaultKBSPort)}, stopCh, readyCh, io.Discard, io.Discard)
	if err != nil {
		return 0, nil, fmt.Errorf("create port forwarder: %w", err)
	}

	forwardErr := make(chan error, 1)
	go func() {
		forwardErr <- fw.ForwardPorts()
	}()

	select {
	case <-ctx.Done():
		close(stopCh)
		return 0, nil, fmt.Errorf("context cancelled before port-forward ready: %w", ctx.Err())
	case fwErr := <-forwardErr:
		return 0, nil, fmt.Errorf("port-forward failed to start: %w", fwErr)
	case <-readyCh:
		// forward is ready
	}

	ports, err := fw.GetPorts()
	if err != nil {
		close(stopCh)
		return 0, nil, fmt.Errorf("get forwarded ports: %w", err)
	}
	if len(ports) == 0 {
		close(stopCh)
		return 0, nil, fmt.Errorf("port forwarder returned no ports")
	}

	var once sync.Once
	stopFn := func() { once.Do(func() { close(stopCh) }) }

	return ports[0].Local, stopFn, nil
}

func ensureNamespace(ctx context.Context, clientset kubernetes.Interface, namespace string) error {
	// Try to create the namespace directly. This is simpler and more reliable
	// than checking existence first:
	// - If namespace doesn't exist: creates it
	// - If namespace exists: AlreadyExists error is ignored
	// - If user lacks create permission but namespace exists: subsequent
	//   operations will work (or fail with clear permission errors)
	_, err := clientset.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: namespace},
	}, metav1.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		// Ignore Forbidden — namespace likely exists but user lacks create permission.
		// Subsequent operations will fail appropriately if it truly doesn't exist.
		if !apierrors.IsForbidden(err) {
			return fmt.Errorf("failed to create namespace %s: %w", namespace, err)
		}
	}
	return nil
}

func applyManifest(ctx context.Context, yaml string) error {
	cmd := exec.CommandContext(ctx, "kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(yaml)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("kubectl apply failed: %w\n%s", err, output)
	}
	return nil
}

// createAuthSecretFromKeys loads or generates an Ed25519 private key, persists
// it to authDir/private.key, creates a Kubernetes Secret containing only the
// public key (for KBS JWT verification), and returns the private key so Deploy
// can call the KBS admin API immediately.
//
// If a valid key already exists at authDir/private.key it is reused, making
// the function idempotent across Deploy retries after partial failures.
func createAuthSecretFromKeys(ctx context.Context, namespace, authDir string) (ed25519.PrivateKey, error) {
	if err := os.MkdirAll(authDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create auth directory %s: %w", authDir, err)
	}

	privateKey, err := loadOrGeneratePrivateKey(filepath.Join(authDir, "private.key"))
	if err != nil {
		return nil, err
	}

	// Derive the public key to put in the K8s Secret.
	pubKey, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("unexpected public key type from Ed25519 private key")
	}
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicKeyBytes})

	// Write only the public key to a temporary directory for the secret.
	// The private key must never be stored in the cluster.
	tmpDir, err := os.MkdirTemp("", "trustee-keys-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer func() {
		if err := os.RemoveAll(tmpDir); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to remove temp directory %s: %v\n", tmpDir, err)
		}
	}()

	tmpPubPath := filepath.Join(tmpDir, "public.pub")
	if err := os.WriteFile(tmpPubPath, publicKeyPEM, 0600); err != nil {
		return nil, fmt.Errorf("failed to write public key to temp dir: %w", err)
	}

	// #nosec G204 - namespace is from function parameter (application-controlled), path is from os.MkdirTemp
	cmd := exec.CommandContext(ctx, "kubectl", "create", "secret", "generic",
		"kbs-auth-public-key", "-n", namespace,
		fmt.Sprintf("--from-file=%s", tmpPubPath),
		"--dry-run=client", "-o", "yaml")
	secretYAML, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to create secret YAML: %w\n%s", err, secretYAML)
	}

	if err := applyManifest(ctx, string(secretYAML)); err != nil {
		return nil, err
	}

	return privateKey, nil
}

// loadOrGeneratePrivateKey returns the Ed25519 private key at keyPath.
// If the file already exists it is parsed and returned — enabling Deploy to be
// retried after a partial failure without manual cleanup.
// If the file does not exist a new key pair is generated and persisted
// atomically (temp-file + rename) so a partial write never corrupts an
// existing key.
// Any file-system error other than ErrNotExist is returned immediately.
func loadOrGeneratePrivateKey(keyPath string) (ed25519.PrivateKey, error) {
	// #nosec G304 -- keyPath is constructed from the user-controlled authDir, resolved and cleaned by DefaultAuthDir
	pemData, readErr := os.ReadFile(keyPath)
	if readErr == nil {
		// File exists — check permissions before using it.
		// A world- or group-readable private key is a credential leak.
		info, err := os.Stat(keyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to stat existing key at %s: %w", keyPath, err)
		}
		if info.Mode().Perm()&0077 != 0 {
			return nil, fmt.Errorf("existing key at %s has overly permissive mode %04o; group/other permissions must not be set", keyPath, info.Mode().Perm())
		}

		// Parse and return the existing key.
		block, _ := pem.Decode(pemData)
		if block == nil {
			return nil, fmt.Errorf("existing key at %s is not valid PEM", keyPath)
		}
		raw, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse existing key at %s: %w", keyPath, err)
		}
		key, ok := raw.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("existing key at %s is not an Ed25519 private key (got %T)", keyPath, raw)
		}
		return key, nil
	}
	if !errors.Is(readErr, os.ErrNotExist) {
		return nil, fmt.Errorf("failed to read key at %s: %w", keyPath, readErr)
	}

	// File does not exist — generate a new key and persist it.
	_, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyBytes})

	// Write via temp file in the same directory, then rename for atomicity.
	tmpKey, err := os.CreateTemp(filepath.Dir(keyPath), ".private.key.*")
	if err != nil {
		return nil, fmt.Errorf("failed to stage private key: %w", err)
	}
	staged := true
	defer func() {
		if staged {
			_ = os.Remove(tmpKey.Name())
		}
	}()
	if err := tmpKey.Chmod(0600); err != nil {
		_ = tmpKey.Close()
		return nil, fmt.Errorf("failed to set key file permissions: %w", err)
	}
	if _, err := tmpKey.Write(privateKeyPEM); err != nil {
		_ = tmpKey.Close()
		return nil, fmt.Errorf("failed to write private key: %w", err)
	}
	if err := tmpKey.Close(); err != nil {
		return nil, fmt.Errorf("failed to close staged key file: %w", err)
	}
	if err := os.Rename(tmpKey.Name(), keyPath); err != nil {
		return nil, fmt.Errorf("failed to install private key at %s: %w", keyPath, err)
	}
	staged = false

	return privateKey, nil
}

func buildConfigMapsManifest(namespace string) string {
	return fmt.Sprintf(`
apiVersion: v1
kind: ConfigMap
metadata:
  name: kbs-config-cm
  namespace: %s
data:
  kbs-config.toml: |
    [http_server]
    sockets = ["0.0.0.0:%d"]
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
    type = "InsecureAllowAll"

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
`, namespace, defaultKBSPort, namespace, namespace)
}

func deployConfigMaps(ctx context.Context, namespace string) error {
	return applyManifest(ctx, buildConfigMapsManifest(namespace))
}

func deployPCCSConfigMap(ctx context.Context, namespace, pccsURL string) error {
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

	return applyManifest(ctx, manifest)
}

func buildKBSManifest(cfg *Config) string {
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

	return fmt.Sprintf(`
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
        - containerPort: %d
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
  - port: %d
    targetPort: %d
    protocol: TCP
`, cfg.Namespace, cfg.KBSImage, defaultKBSPort, volumeMounts, volumes, cfg.ServiceName, cfg.Namespace, defaultKBSPort, defaultKBSPort)
}

func deployKBS(ctx context.Context, cfg *Config) error {
	return applyManifest(ctx, buildKBSManifest(cfg))
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
	// #nosec G204 -- namespace/secret names are from trusted config, not user input
	cmd := exec.Command("kubectl", "get", "pod", "-n", trusteeNamespace,
		"-l", trusteeLabel, "-o", "jsonpath={.items[0].metadata.name}")
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
	// #nosec G204 -- namespace/secret names are from trusted config, not user input
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

