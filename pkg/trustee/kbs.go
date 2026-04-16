package trustee

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8swatch "k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/confidential-devhub/cococtl/pkg/kbsclient"
)

// errWatchClosed is returned by watchUntilReady when the API server closes the
// watch channel normally (e.g. server-side timeout).  The caller should
// re-list and re-watch rather than treating this as a terminal error.
var errWatchClosed = errors.New("watch channel closed")

// UploadResource uploads a single resource to Trustee KBS via the KBS admin HTTP API.
// The resourcePath should be relative (e.g., "default/sidecar-tls/server-cert").
// The data is the raw bytes to upload.
func UploadResource(ctx context.Context, client *kbsclient.Client, resourcePath string, data []byte) error {
	return client.SetResource(ctx, resourcePath, data)
}

// UploadResources uploads multiple resources to Trustee KBS via the KBS admin HTTP API.
// Each resource is specified as a map entry where key is the resource path
// (e.g., "default/sidecar-tls/server-cert") and value is the data bytes.
func UploadResources(ctx context.Context, client *kbsclient.Client, resources map[string][]byte) error {
	for path, data := range resources {
		if err := client.SetResource(ctx, path, data); err != nil {
			return fmt.Errorf("upload %s: %w", path, err)
		}
	}
	return nil
}

// NewClientWithPortForward creates a kbsclient.Client connected to the KBS pod via a
// temporary port-forward. The caller must invoke the returned stop function when done
// to release the port-forward. ctx bounds only the port-forward handshake; subsequent
// HTTP calls use the kbsclient's own per-request timeout.
//
// authDir is the directory containing private.key (the Ed25519 key written during init).
// If empty, DefaultAuthDir is used.
func NewClientWithPortForward(ctx context.Context, restConfig *rest.Config, clientset kubernetes.Interface, namespace, authDir string) (*kbsclient.Client, func(), error) {
	resolvedAuthDir, err := DefaultAuthDir(authDir)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to resolve auth directory: %w", err)
	}

	// Wait for a KBS pod to be ready before attempting the port-forward.
	// Bound by kbsReadyTimeout so the caller does not need to set a deadline.
	waitCtx, waitCancel := context.WithTimeout(ctx, kbsReadyTimeout)
	defer waitCancel()
	if err := WaitForKBSReady(waitCtx, clientset, namespace); err != nil {
		return nil, nil, fmt.Errorf("KBS pod not ready: %w", err)
	}

	podName, err := getReadyKBSPodName(waitCtx, clientset, namespace)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to find ready KBS pod: %w", err)
	}

	// Port-forward; the context only bounds the handshake, not the forward lifetime.
	portFwdCtx, portFwdCancel := context.WithTimeout(ctx, kbsAdminTimeout)
	localPort, stopForward, err := portForwardKBSPod(portFwdCtx, restConfig, clientset, namespace, podName)
	portFwdCancel()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to port-forward to KBS pod: %w", err)
	}

	// Load the Ed25519 private key written by Deploy/init.
	keyPath := filepath.Join(resolvedAuthDir, "private.key")
	// #nosec G304 -- keyPath is constructed from DefaultAuthDir, an application-controlled path
	pemData, err := os.ReadFile(keyPath)
	if err != nil {
		stopForward()
		return nil, nil, fmt.Errorf("failed to read KBS private key from %s (run 'cococtl init' first): %w", keyPath, err)
	}

	kbsURL := fmt.Sprintf("http://127.0.0.1:%d", localPort)
	kbsClient, err := kbsclient.NewFromPEM(kbsURL, pemData, nil)
	if err != nil {
		stopForward()
		return nil, nil, fmt.Errorf("failed to create KBS client: %w", err)
	}

	return kbsClient, stopForward, nil
}

// GetKBSPodName retrieves the name of the KBS pod in the specified namespace.
func GetKBSPodName(ctx context.Context, clientset kubernetes.Interface, namespace string) (string, error) {
	pods, err := clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: trusteeLabel,
	})
	if err != nil {
		return "", fmt.Errorf("failed to list pods: %w", err)
	}

	if len(pods.Items) == 0 {
		return "", fmt.Errorf("no KBS pod found in namespace %s", namespace)
	}

	return pods.Items[0].Name, nil
}

// WaitForKBSReady waits for a KBS pod to reach the Ready condition using the
// Kubernetes watch API.  It re-lists and re-watches if the API server closes
// the watch channel normally.  The caller is responsible for setting a deadline
// on ctx if a hard timeout is required.
func WaitForKBSReady(ctx context.Context, clientset kubernetes.Interface, namespace string) error {
	for {
		// List to get the current resource version and short-circuit if a pod
		// is already ready.
		pods, err := clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
			LabelSelector: trusteeLabel,
		})
		if err != nil {
			return fmt.Errorf("failed to list KBS pods: %w", err)
		}

		for i := range pods.Items {
			if isPodReady(&pods.Items[i]) {
				return nil
			}
		}

		// Watch from the resource version returned by List to avoid
		// re-processing events already reflected in the List response.
		watcher, err := clientset.CoreV1().Pods(namespace).Watch(ctx, metav1.ListOptions{
			LabelSelector:   trusteeLabel,
			ResourceVersion: pods.ResourceVersion,
		})
		if err != nil {
			return fmt.Errorf("failed to watch KBS pods: %w", err)
		}

		err = watchUntilReady(ctx, watcher.ResultChan())
		watcher.Stop()

		if err == nil {
			return nil // a pod became ready
		}
		if !errors.Is(err, errWatchClosed) {
			return err // context cancelled/deadline, or Error event
		}
		// Watch channel closed normally (server-side timeout, connection reset,
		// etc.) — re-list and re-watch.
	}
}

// watchUntilReady drains ch until a ready pod is observed, the context is
// done, an Error event arrives, or the channel closes.  It returns nil on
// success, errWatchClosed if the channel closes normally, and a descriptive
// error otherwise.
func watchUntilReady(ctx context.Context, ch <-chan k8swatch.Event) error {
	for {
		select {
		case <-ctx.Done():
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return fmt.Errorf("timed out waiting for KBS pod to be ready: %w", ctx.Err())
			}
			return fmt.Errorf("cancelled waiting for KBS pod to be ready: %w", ctx.Err())
		case event, ok := <-ch:
			if !ok {
				return errWatchClosed
			}
			switch event.Type {
			case k8swatch.Error:
				if status, ok := event.Object.(*metav1.Status); ok {
					return fmt.Errorf("error watching KBS pod: %s: %s", status.Reason, status.Message)
				}
				return fmt.Errorf("error event received while watching KBS pod")
			case k8swatch.Deleted:
				// Pod deleted during a rollout; a replacement will appear.
				// Continue watching rather than failing.
			case k8swatch.Added, k8swatch.Modified:
				pod, ok := event.Object.(*corev1.Pod)
				if ok && isPodReady(pod) {
					return nil
				}
			}
		}
	}
}

// getReadyKBSPodName returns the name of the first KBS pod that is currently
// in the Ready state.  It is used after WaitForKBSReady to guarantee the
// selected pod is still ready, guarding against rollouts where GetKBSPodName
// might pick a Terminating pod.
func getReadyKBSPodName(ctx context.Context, clientset kubernetes.Interface, namespace string) (string, error) {
	pods, err := clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: trusteeLabel,
	})
	if err != nil {
		return "", fmt.Errorf("failed to list KBS pods: %w", err)
	}
	for i := range pods.Items {
		if isPodReady(&pods.Items[i]) {
			return pods.Items[i].Name, nil
		}
	}
	return "", fmt.Errorf("no ready KBS pod found in namespace %s", namespace)
}

// isPodReady returns true if the pod's Ready condition is True.
func isPodReady(pod *corev1.Pod) bool {
	for _, cond := range pod.Status.Conditions {
		if cond.Type == corev1.PodReady && cond.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

