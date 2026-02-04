// Package k8s provides a shared Kubernetes client factory with kubectl-compatible
// kubeconfig discovery and namespace resolution.
package k8s

import (
	"fmt"
	"os"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	// inClusterNamespacePath is the path to the namespace file in a Kubernetes pod.
	inClusterNamespacePath = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
)

// Client wraps a Kubernetes clientset with resolved configuration.
type Client struct {
	// Clientset is the Kubernetes client interface. Using Interface (not *Clientset)
	// allows for easy testing with fake.NewSimpleClientset().
	Clientset kubernetes.Interface

	// Namespace is the resolved default namespace for operations.
	Namespace string

	// Config is the underlying REST config for advanced use cases.
	Config *rest.Config
}

// ClientOptions configures client creation.
type ClientOptions struct {
	// Kubeconfig is an explicit kubeconfig path. If empty, standard discovery is used:
	// KUBECONFIG env -> ~/.kube/config -> in-cluster config.
	Kubeconfig string

	// Context is an explicit context name. If empty, current-context is used.
	Context string

	// Namespace is an explicit namespace. If empty, namespace is resolved from:
	// kubeconfig context -> in-cluster namespace file -> "default".
	Namespace string

	// Timeout is the default timeout for API operations. If zero, no timeout is set.
	Timeout time.Duration
}

// NewClient creates a Kubernetes client with kubectl-compatible kubeconfig discovery.
//
// Kubeconfig discovery order (same as kubectl):
//  1. opts.Kubeconfig (if provided)
//  2. KUBECONFIG environment variable
//  3. ~/.kube/config
//  4. In-cluster config (when running inside a pod)
//
// Namespace resolution order:
//  1. opts.Namespace (if provided)
//  2. Namespace from kubeconfig current context
//  3. In-cluster namespace file (/var/run/secrets/kubernetes.io/serviceaccount/namespace)
//  4. "default"
func NewClient(opts ClientOptions) (*Client, error) {
	config, namespace, err := loadConfig(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to load kubernetes config: %w", err)
	}

	// Apply timeout if specified
	if opts.Timeout > 0 {
		config.Timeout = opts.Timeout
	}

	// Create clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes client: %w", err)
	}

	// Override namespace if explicitly provided
	if opts.Namespace != "" {
		namespace = opts.Namespace
	}

	// Ensure we always have a namespace
	if namespace == "" {
		namespace = getInClusterNamespace("")
	}

	return &Client{
		Clientset: clientset,
		Namespace: namespace,
		Config:    config,
	}, nil
}

// GetCurrentNamespace returns the namespace from the current kubeconfig context.
// This is a standalone function for cases where you only need the namespace
// without creating a full client.
//
// Resolution order:
//  1. Namespace from kubeconfig current context
//  2. In-cluster namespace file
//  3. "default"
func GetCurrentNamespace() (string, error) {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	configOverrides := &clientcmd.ConfigOverrides{}

	kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		loadingRules,
		configOverrides,
	)

	namespace, _, err := kubeConfig.Namespace()
	if err != nil {
		// If kubeconfig doesn't exist or is invalid, try in-cluster
		return getInClusterNamespace(""), nil
	}

	if namespace == "" {
		namespace = getInClusterNamespace("")
	}

	return namespace, nil
}

// WrapError wraps a Kubernetes API error with operation context.
// It provides user-friendly messages for common error types.
func WrapError(err error, operation, resource, namespace string) error {
	if err == nil {
		return nil
	}

	if apierrors.IsNotFound(err) {
		if namespace != "" {
			return fmt.Errorf("%s not found in namespace %s", resource, namespace)
		}
		return fmt.Errorf("%s not found", resource)
	}

	if apierrors.IsForbidden(err) {
		if namespace != "" {
			return fmt.Errorf("permission denied: cannot %s %s in namespace %s", operation, resource, namespace)
		}
		return fmt.Errorf("permission denied: cannot %s %s", operation, resource)
	}

	if namespace != "" {
		return fmt.Errorf("failed to %s %s in namespace %s: %w", operation, resource, namespace, err)
	}
	return fmt.Errorf("failed to %s %s: %w", operation, resource, err)
}

// loadConfig loads the Kubernetes config using kubectl-compatible discovery.
func loadConfig(opts ClientOptions) (*rest.Config, string, error) {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()

	// Use explicit kubeconfig path if provided
	if opts.Kubeconfig != "" {
		loadingRules.ExplicitPath = opts.Kubeconfig
	}

	configOverrides := &clientcmd.ConfigOverrides{}

	// Use explicit context if provided
	if opts.Context != "" {
		configOverrides.CurrentContext = opts.Context
	}

	kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		loadingRules,
		configOverrides,
	)

	// Get namespace from context
	namespace, _, err := kubeConfig.Namespace()
	if err != nil {
		// Namespace resolution failed, but we might still get a valid config
		namespace = ""
	}

	// Try to get client config from kubeconfig
	config, err := kubeConfig.ClientConfig()
	if err != nil {
		// Kubeconfig failed, try in-cluster config
		config, err = rest.InClusterConfig()
		if err != nil {
			return nil, "", fmt.Errorf("unable to load kubeconfig (tried KUBECONFIG, ~/.kube/config, in-cluster): %w", err)
		}
		// For in-cluster, namespace comes from the namespace file
		namespace = getInClusterNamespace(namespace)
	}

	return config, namespace, nil
}

// getInClusterNamespace returns the namespace from the in-cluster namespace file,
// or the override if provided, or "default" as a fallback.
func getInClusterNamespace(override string) string {
	if override != "" {
		return override
	}

	data, err := os.ReadFile(inClusterNamespacePath)
	if err != nil {
		return "default"
	}

	ns := string(data)
	if ns == "" {
		return "default"
	}

	return ns
}
