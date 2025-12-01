package trustee

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const kbsRepositoryPath = "/opt/confidential-containers/kbs/repository"

// UploadResource uploads a single resource to Trustee KBS.
// The resourcePath should be relative (e.g., "default/sidecar-tls/server-cert").
// The data is the raw bytes to upload.
func UploadResource(namespace, resourcePath string, data []byte) error {
	resources := []SecretResource{
		{
			URI:  "kbs:///" + resourcePath,
			Data: data,
		},
	}

	return populateSecrets(namespace, resources)
}

// UploadResources uploads multiple resources to Trustee KBS in a single operation.
// Each resource is specified as a map entry where key is the resource path
// (e.g., "default/sidecar-tls/server-cert") and value is the data bytes.
func UploadResources(namespace string, resources map[string][]byte) error {
	if len(resources) == 0 {
		return nil
	}

	secretResources := make([]SecretResource, 0, len(resources))
	for path, data := range resources {
		secretResources = append(secretResources, SecretResource{
			URI:  "kbs:///" + path,
			Data: data,
		})
	}

	return populateSecrets(namespace, secretResources)
}

// GetKBSPodName retrieves the name of the KBS pod in the specified namespace.
func GetKBSPodName(namespace string) (string, error) {
	cmd := exec.Command("kubectl", "get", "pod", "-n", namespace,
		"-l", "app=kbs", "-o", "jsonpath={.items[0].metadata.name}")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to get KBS pod: %w\n%s", err, output)
	}

	podName := strings.TrimSpace(string(output))
	if podName == "" {
		return "", fmt.Errorf("no KBS pod found in namespace %s", namespace)
	}

	return podName, nil
}

// WaitForKBSReady waits for the KBS pod to be ready.
func WaitForKBSReady(namespace string) error {
	podName, err := GetKBSPodName(namespace)
	if err != nil {
		return err
	}

	// #nosec G204 - namespace is from function parameter, podName is from kubectl get output
	cmd := exec.Command("kubectl", "wait", "--for=condition=ready", "--timeout=120s",
		"-n", namespace, fmt.Sprintf("pod/%s", podName))
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("pod not ready: %w\n%s", err, output)
	}

	return nil
}

// populateSecrets is now internal but still used by the original Deploy function.
// It uploads multiple secrets to KBS via kubectl cp.
func populateSecrets(namespace string, secrets []SecretResource) error {
	if len(secrets) == 0 {
		return nil
	}

	podName, err := GetKBSPodName(namespace)
	if err != nil {
		return err
	}

	if err := WaitForKBSReady(namespace); err != nil {
		return err
	}

	tmpDir, err := os.MkdirTemp("", "kbs-secrets-*")
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer func() {
		if err := os.RemoveAll(tmpDir); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to remove temp directory %s: %v\n", tmpDir, err)
		}
	}()

	for _, secret := range secrets {
		resourcePath := strings.TrimPrefix(secret.URI, "kbs://")
		resourcePath = strings.TrimPrefix(resourcePath, "/")

		fullPath := filepath.Join(tmpDir, resourcePath)
		if err := os.MkdirAll(filepath.Dir(fullPath), 0750); err != nil {
			return fmt.Errorf("failed to create directory: %w", err)
		}

		if err := os.WriteFile(fullPath, secret.Data, 0600); err != nil {
			return fmt.Errorf("failed to write secret: %w", err)
		}
	}

	// #nosec G204 - namespace is from function parameter, tmpDir is from os.MkdirTemp, podName is from kubectl get
	cmd := exec.Command("kubectl", "cp", "-n", namespace,
		tmpDir+"/.", podName+":"+kbsRepositoryPath+"/")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to copy secrets to KBS: %w\n%s", err, output)
	}

	return nil
}
