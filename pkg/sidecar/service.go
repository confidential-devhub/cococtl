// Package sidecar handles injection of the secure access sidecar container into manifests.
package sidecar

import (
	"fmt"

	"github.com/confidential-devhub/cococtl/pkg/config"
	"github.com/confidential-devhub/cococtl/pkg/manifest"
)

// GenerateService creates a Kubernetes Service manifest for the sidecar.
// The Service exposes the HTTPS port of the sidecar using the same labels
// as the workload pods.
// Returns nil map if sidecar is not enabled.
func GenerateService(m *manifest.Manifest, cfg *config.CocoConfig, appName, namespace string) (map[string]interface{}, error) {
	if !cfg.Sidecar.Enabled {
		return make(map[string]interface{}), nil
	}

	// Get labels from the pod template to use as selectors
	labels, err := m.GetPodLabels()
	if err != nil {
		return nil, fmt.Errorf("failed to get pod labels: %w", err)
	}

	// If no labels found, create a default label
	if len(labels) == 0 {
		labels = map[string]interface{}{
			"app": appName,
		}
	}

	serviceName := fmt.Sprintf("%s-sidecar", appName)

	service := map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Service",
		"metadata": map[string]interface{}{
			"name":      serviceName,
			"namespace": namespace,
			"labels": map[string]interface{}{
				"app":       appName,
				"component": "coco-sidecar",
			},
		},
		"spec": map[string]interface{}{
			"type":     "ClusterIP",
			"selector": labels,
			"ports": []interface{}{
				map[string]interface{}{
					"name":       "https",
					"port":       cfg.Sidecar.HTTPSPort,
					"targetPort": cfg.Sidecar.HTTPSPort,
					"protocol":   "TCP",
				},
			},
		},
	}

	return service, nil
}
