// Package sidecar handles injection of the secure access sidecar container into manifests.
package sidecar

import (
	"fmt"

	"github.com/confidential-devhub/cococtl/pkg/config"
	"github.com/confidential-devhub/cococtl/pkg/manifest"
)

// Inject adds the secure access sidecar container to the manifest.
// It validates the sidecar configuration and builds the container specification
// before adding it to the manifest.
// The appName is used to generate per-app certificate URIs in KBS.
// The namespace is used to construct the KBS URI path.
func Inject(m *manifest.Manifest, cfg *config.CocoConfig, appName, namespace string) error {
	if !cfg.Sidecar.Enabled {
		return nil
	}

	if err := validateConfig(cfg); err != nil {
		return fmt.Errorf("invalid sidecar config: %w", err)
	}

	container := buildContainer(cfg, appName, namespace)

	if err := m.AddSidecarContainer(container); err != nil {
		return fmt.Errorf("failed to add sidecar container: %w", err)
	}

	return nil
}

// validateConfig ensures required sidecar configuration is present.
// Note: TLS cert URIs are not required in config as they are generated per-app.
func validateConfig(cfg *config.CocoConfig) error {
	if cfg.Sidecar.Image == "" {
		return fmt.Errorf("sidecar image is required")
	}
	if cfg.Sidecar.HTTPSPort <= 0 || cfg.Sidecar.HTTPSPort > 65535 {
		return fmt.Errorf("invalid https_port: must be between 1 and 65535")
	}
	return nil
}

// GenerateCertURIs generates per-app certificate URIs for the sidecar.
// Format: kbs:///<namespace>/sidecar-tls-<appName>/server-{cert|key}
//
//	kbs:///default/sidecar-tls/client-ca (global, always in default namespace)
func GenerateCertURIs(appName, namespace string) (serverCertURI, serverKeyURI, clientCAURI string) {
	certPrefix := fmt.Sprintf("kbs:///%s/sidecar-tls-%s", namespace, appName)
	serverCertURI = certPrefix + "/server-cert"
	serverKeyURI = certPrefix + "/server-key"
	// Client CA is always stored in "default" namespace for consistency
	clientCAURI = "kbs:///default/sidecar-tls/client-ca"
	return
}

// buildContainer creates the sidecar container specification with per-app certificate URIs.
func buildContainer(cfg *config.CocoConfig, appName, namespace string) map[string]interface{} {
	// Generate per-app certificate URIs
	serverCertURI, serverKeyURI, clientCAURI := GenerateCertURIs(appName, namespace)

	// Environment variables for KBS URIs and pod metadata
	env := []interface{}{
		map[string]interface{}{
			"name":  "TLS_CERT_URI",
			"value": serverCertURI,
		},
		map[string]interface{}{
			"name":  "TLS_KEY_URI",
			"value": serverKeyURI,
		},
		map[string]interface{}{
			"name":  "CLIENT_CA_URI",
			"value": clientCAURI,
		},
		map[string]interface{}{
			"name":  "HTTPS_PORT",
			"value": fmt.Sprintf("%d", cfg.Sidecar.HTTPSPort),
		},
		// Pod metadata from Downward API
		map[string]interface{}{
			"name": "POD_NAME",
			"valueFrom": map[string]interface{}{
				"fieldRef": map[string]interface{}{
					"fieldPath": "metadata.name",
				},
			},
		},
		map[string]interface{}{
			"name": "POD_NAMESPACE",
			"valueFrom": map[string]interface{}{
				"fieldRef": map[string]interface{}{
					"fieldPath": "metadata.namespace",
				},
			},
		},
	}

	// Add forward port if configured
	if cfg.Sidecar.ForwardPort > 0 {
		env = append(env, map[string]interface{}{
			"name":  "FORWARD_PORT",
			"value": fmt.Sprintf("%d", cfg.Sidecar.ForwardPort),
		})
	}

	// Container ports
	ports := []interface{}{
		map[string]interface{}{
			"containerPort": cfg.Sidecar.HTTPSPort,
			"name":          "https",
			"protocol":      "TCP",
		},
	}

	// Resource limits and requests
	resources := map[string]interface{}{}
	if cfg.Sidecar.CPULimit != "" || cfg.Sidecar.MemoryLimit != "" {
		limits := map[string]interface{}{}
		if cfg.Sidecar.CPULimit != "" {
			limits["cpu"] = cfg.Sidecar.CPULimit
		}
		if cfg.Sidecar.MemoryLimit != "" {
			limits["memory"] = cfg.Sidecar.MemoryLimit
		}
		resources["limits"] = limits
	}
	if cfg.Sidecar.CPURequest != "" || cfg.Sidecar.MemoryRequest != "" {
		requests := map[string]interface{}{}
		if cfg.Sidecar.CPURequest != "" {
			requests["cpu"] = cfg.Sidecar.CPURequest
		}
		if cfg.Sidecar.MemoryRequest != "" {
			requests["memory"] = cfg.Sidecar.MemoryRequest
		}
		resources["requests"] = requests
	}

	// Build container
	container := map[string]interface{}{
		"name":  "coco-secure-access",
		"image": cfg.Sidecar.Image,
		"ports": ports,
		"env":   env,
	}

	if len(resources) > 0 {
		container["resources"] = resources
	}

	return container
}
