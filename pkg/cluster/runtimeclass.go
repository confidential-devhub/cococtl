// Package cluster provides utilities for interacting with Kubernetes clusters.
package cluster

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

// runtimeClassList represents the JSON response from kubectl get runtimeclasses
type runtimeClassList struct {
	Items []struct {
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
		Handler string `json:"handler"`
	} `json:"items"`
}

// DetectRuntimeClass attempts to auto-detect a RuntimeClass with SNP or TDX support.
// It retrieves all RuntimeClasses from the cluster and selects the first one whose
// handler contains "snp" or "tdx" (case-insensitive).
// Returns the default RuntimeClass if:
// - There's an error retrieving RuntimeClasses (permissions, kubectl not available, etc.)
// - No RuntimeClasses have handlers containing "snp" or "tdx"
func DetectRuntimeClass(defaultRuntimeClass string) string {
	// #nosec G204 -- static command with no user-controlled input
	cmd := exec.Command("kubectl", "get", "runtimeclasses", "-o", "json")

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		// Error retrieving RuntimeClasses (permissions, kubectl not available, etc.)
		// Return default
		fmt.Printf("Unable to detect RuntimeClasses: %v (stderr: %s) (using default: %s)\n", err, strings.TrimSpace(stderr.String()), defaultRuntimeClass)
		return defaultRuntimeClass
	}

	var rcList runtimeClassList
	if err := json.Unmarshal(stdout.Bytes(), &rcList); err != nil {
		// Error parsing JSON, return default
		fmt.Printf("Unable to parse RuntimeClasses: %v (using default: %s)\n", err, defaultRuntimeClass)
		return defaultRuntimeClass
	}

	// Look for RuntimeClasses with handlers containing "snp" or "tdx"
	for _, rc := range rcList.Items {
		handler := strings.ToLower(rc.Handler)
		if strings.Contains(handler, "snp") || strings.Contains(handler, "tdx") {
			fmt.Printf("Detected RuntimeClass: %s\n", rc.Metadata.Name)
			return rc.Metadata.Name
		}
	}

	// No matching RuntimeClass found, return default
	fmt.Printf("No SNP/TDX RuntimeClass found (using default: %s)\n", defaultRuntimeClass)
	return defaultRuntimeClass
}
