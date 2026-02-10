// Package cluster provides utilities for interacting with Kubernetes clusters.
package cluster

import (
	"context"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// DetectRuntimeClass attempts to auto-detect a RuntimeClass with SNP or TDX support.
// It retrieves all RuntimeClasses from the cluster and selects the first one whose
// handler contains "snp" or "tdx" (case-insensitive).
// Returns the default RuntimeClass if:
// - There's an error retrieving RuntimeClasses (permissions, cluster unreachable, etc.)
// - No RuntimeClasses have handlers containing "snp" or "tdx"
func DetectRuntimeClass(ctx context.Context, clientset kubernetes.Interface, defaultRuntimeClass string) string {
	rcs, err := clientset.NodeV1().RuntimeClasses().List(ctx, metav1.ListOptions{})
	if err != nil {
		fmt.Printf("Unable to detect RuntimeClasses: %v (using default: %s)\n", err, defaultRuntimeClass)
		return defaultRuntimeClass
	}

	// Look for RuntimeClasses with handlers containing "snp" or "tdx"
	for _, rc := range rcs.Items {
		handler := strings.ToLower(rc.Handler)
		if strings.Contains(handler, "snp") || strings.Contains(handler, "tdx") {
			fmt.Printf("Detected RuntimeClass: %s\n", rc.Name)
			return rc.Name
		}
	}

	// No matching RuntimeClass found, return default
	fmt.Printf("No SNP/TDX RuntimeClass found (using default: %s)\n", defaultRuntimeClass)
	return defaultRuntimeClass
}
