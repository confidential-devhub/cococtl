// Package cluster provides utilities for interacting with Kubernetes clusters.
package cluster

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// GetNodeIPs retrieves IP addresses of all nodes in the cluster.
// It attempts to get ExternalIP first, falling back to InternalIP if unavailable.
// Returns a deduplicated list of node IP addresses.
func GetNodeIPs() ([]string, error) {
	// Try external IPs first
	externalIPs, err := getNodeIPsByType("ExternalIP")
	if err == nil && len(externalIPs) > 0 {
		return externalIPs, nil
	}

	// Fall back to internal IPs
	internalIPs, err := getNodeIPsByType("InternalIP")
	if err != nil {
		return nil, fmt.Errorf("failed to get node IPs: %w", err)
	}

	if len(internalIPs) == 0 {
		return nil, fmt.Errorf("no node IPs found in cluster")
	}

	return internalIPs, nil
}

// getNodeIPsByType retrieves node IPs of a specific address type.
func getNodeIPsByType(addressType string) ([]string, error) {
	jsonPath := fmt.Sprintf("{.items[*].status.addresses[?(@.type==\"%s\")].address}", addressType)

	// #nosec G204 -- addressType is controlled, only called with "ExternalIP" or "InternalIP"
	cmd := exec.Command("kubectl", "get", "nodes",
		"-o", fmt.Sprintf("jsonpath=%s", jsonPath))

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("kubectl get nodes failed: %w: %s", err, stderr.String())
	}

	output := strings.TrimSpace(stdout.String())
	if output == "" {
		return nil, nil
	}

	// Split by spaces and deduplicate
	ips := strings.Fields(output)
	return deduplicateStrings(ips), nil
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
