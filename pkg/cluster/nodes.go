// Package cluster provides utilities for interacting with Kubernetes clusters.
package cluster

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// GetNodeIPs retrieves IP addresses of all nodes in the cluster.
// It attempts to get ExternalIP first, falling back to InternalIP if unavailable.
// Returns a deduplicated list of node IP addresses.
func GetNodeIPs(ctx context.Context, clientset kubernetes.Interface) ([]string, error) {
	nodes, err := clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list nodes: %w", err)
	}

	// Try external IPs first
	externalIPs := extractAddresses(nodes.Items, corev1.NodeExternalIP)
	if len(externalIPs) > 0 {
		return deduplicateStrings(externalIPs), nil
	}

	// Fall back to internal IPs
	internalIPs := extractAddresses(nodes.Items, corev1.NodeInternalIP)
	if len(internalIPs) == 0 {
		return nil, fmt.Errorf("no node IPs found in cluster")
	}

	return deduplicateStrings(internalIPs), nil
}

// extractAddresses extracts addresses of a specific type from all nodes.
func extractAddresses(nodes []corev1.Node, addrType corev1.NodeAddressType) []string {
	var addresses []string
	for _, node := range nodes {
		for _, addr := range node.Status.Addresses {
			if addr.Type == addrType {
				addresses = append(addresses, addr.Address)
			}
		}
	}
	return addresses
}

// deduplicateStrings removes duplicate entries from a string slice.
func deduplicateStrings(input []string) []string {
	seen := make(map[string]bool)
	result := []string{}

	for _, item := range input {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}

	return result
}
