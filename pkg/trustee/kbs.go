package trustee

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/confidential-devhub/cococtl/pkg/k8s"
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
func GetKBSPodName(ctx context.Context, clientset kubernetes.Interface, namespace string) (string, error) {
	pods, err := clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: "app=kbs",
	})
	if err != nil {
		return "", fmt.Errorf("failed to list pods: %w", err)
	}

	if len(pods.Items) == 0 {
		return "", fmt.Errorf("no KBS pod found in namespace %s", namespace)
	}

	return pods.Items[0].Name, nil
}

// WaitForKBSReady waits for the KBS pod to be ready.
func WaitForKBSReady(ctx context.Context, clientset kubernetes.Interface, namespace string) error {
	podName, err := GetKBSPodName(ctx, clientset, namespace)
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

// It uploads multiple secrets to KBS via kubectl cp.
func populateSecrets(namespace string, secrets []SecretResource) error {
	if len(secrets) == 0 {
		return nil
	}

	// For now, create context here until UploadResource/UploadResources are migrated
	ctx := context.Background()
	client, err := k8s.NewClient(k8s.ClientOptions{})
	if err != nil {
		return fmt.Errorf("failed to create kubernetes client: %w", err)
	}

	podName, err := GetKBSPodName(ctx, client.Clientset, namespace)
	if err != nil {
		return err
	}

	if err := WaitForKBSReady(ctx, client.Clientset, namespace); err != nil {
		return err
	}

	// Use empty prefix for unpredictable temp directory name (more secure)
	tmpDir, err := os.MkdirTemp("", "")
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}

	// Ensure secure cleanup even on panic or error
	defer func() {
		if err := secureDeleteDir(tmpDir); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to securely delete temp directory %s: %v\n", tmpDir, err)
		}
	}()

	for _, secret := range secrets {
		resourcePath := strings.TrimPrefix(secret.URI, "kbs://")
		resourcePath = strings.TrimPrefix(resourcePath, "/")

		fullPath := filepath.Join(tmpDir, resourcePath)
		if err := os.MkdirAll(filepath.Dir(fullPath), 0700); err != nil {
			return fmt.Errorf("failed to create directory: %w", err)
		}

		// Write with strict permissions
		if err := writeSecretFile(fullPath, secret.Data); err != nil {
			return fmt.Errorf("failed to write secret: %w", err)
		}
	}

	// #nosec G204 - namespace is from function parameter, tmpDir is from os.MkdirTemp, podName is from kubectl get
	// Use --no-preserve to avoid tar ownership errors when local files have different uid/gid than container
	cmd := exec.Command("kubectl", "cp", "--no-preserve=true", "-n", namespace,
		tmpDir+"/.", podName+":"+kbsRepositoryPath+"/")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to copy secrets to KBS: %w\n%s", err, output)
	}

	return nil
}

// writeSecretFile writes secret data with strict permissions, bypassing umask.
func writeSecretFile(path string, data []byte) error {
	// #nosec G304 -- Path is constructed from KBS resource URI and tmpDir (both controlled)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := f.Close(); closeErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to close file %s: %v\n", path, closeErr)
		}
	}()

	if _, err := f.Write(data); err != nil {
		return err
	}

	// Explicitly set permissions to ensure 0600 regardless of umask
	return f.Chmod(0600)
}

// secureDeleteDir securely deletes a directory by overwriting all files before removal.
// This prevents forensic recovery of sensitive cryptographic material.
func secureDeleteDir(dir string) error {
	// Walk directory and overwrite all regular files
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Only overwrite regular files, not directories or symlinks
		if info.Mode().IsRegular() {
			if err := secureDeleteFile(path, info.Size()); err != nil {
				// Log but continue - best effort deletion
				fmt.Fprintf(os.Stderr, "Warning: failed to securely delete %s: %v\n", path, err)
			}
		}
		return nil
	})

	if err != nil {
		// Continue with removal even if overwrite failed
		fmt.Fprintf(os.Stderr, "Warning: errors during secure deletion: %v\n", err)
	}

	// Remove the directory after overwriting files
	return os.RemoveAll(dir)
}

// secureDeleteFile overwrites a file with random data before deletion.
// Performs 3-pass overwrite: random, zeros, random
func secureDeleteFile(path string, size int64) error {
	if size == 0 {
		return nil // Empty file, nothing to overwrite
	}

	// #nosec G304 -- Path comes from filepath.Walk in secureDeleteDir, validated as regular file
	f, err := os.OpenFile(path, os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := f.Close(); closeErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to close file %s: %v\n", path, closeErr)
		}
	}()

	// Allocate buffer for overwriting (max 1MB chunks for large files)
	bufSize := int64(1024 * 1024)
	if size < bufSize {
		bufSize = size
	}
	buf := make([]byte, bufSize)

	// Pass 1: Random data
	for written := int64(0); written < size; {
		toWrite := bufSize
		if size-written < bufSize {
			toWrite = size - written
		}
		// Fill buffer with cryptographically secure random data
		if _, err := rand.Read(buf[:toWrite]); err != nil {
			return fmt.Errorf("pass 1 random generation failed: %w", err)
		}
		if _, err := f.Write(buf[:toWrite]); err != nil {
			return fmt.Errorf("pass 1 write failed: %w", err)
		}
		written += toWrite
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("pass 1 sync failed: %w", err)
	}

	// Pass 2: Zeros
	if _, err := f.Seek(0, 0); err != nil {
		return fmt.Errorf("seek before pass 2 failed: %w", err)
	}
	for i := range buf {
		buf[i] = 0
	}
	for written := int64(0); written < size; {
		toWrite := bufSize
		if size-written < bufSize {
			toWrite = size - written
		}
		if _, err := f.Write(buf[:toWrite]); err != nil {
			return fmt.Errorf("pass 2 write failed: %w", err)
		}
		written += toWrite
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("pass 2 sync failed: %w", err)
	}

	// Pass 3: Random data again
	if _, err := f.Seek(0, 0); err != nil {
		return fmt.Errorf("seek before pass 3 failed: %w", err)
	}
	for written := int64(0); written < size; {
		toWrite := bufSize
		if size-written < bufSize {
			toWrite = size - written
		}
		// Fill buffer with cryptographically secure random data
		if _, err := rand.Read(buf[:toWrite]); err != nil {
			return fmt.Errorf("pass 3 random generation failed: %w", err)
		}
		if _, err := f.Write(buf[:toWrite]); err != nil {
			return fmt.Errorf("pass 3 write failed: %w", err)
		}
		written += toWrite
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("pass 3 sync failed: %w", err)
	}

	return nil
}
