package sidecar

import (
	"os"
	"testing"

	"github.com/confidential-devhub/cococtl/pkg/config"
	"github.com/confidential-devhub/cococtl/pkg/manifest"
)

func TestGenerateService(t *testing.T) {
	tests := []struct {
		name      string
		manifest  string
		cfg       *config.CocoConfig
		appName   string
		namespace string
		checkFunc func(t *testing.T, service map[string]interface{})
	}{
		{
			name: "deployment with labels",
			manifest: `apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-app
  namespace: default
spec:
  replicas: 1
  selector:
    matchLabels:
      app: test-app
  template:
    metadata:
      labels:
        app: test-app
        version: v1
    spec:
      containers:
      - name: main
        image: nginx:latest`,
			cfg: &config.CocoConfig{
				Sidecar: config.SidecarConfig{
					Enabled:   true,
					HTTPSPort: 8443,
				},
			},
			appName:   "test-app",
			namespace: "default",
			checkFunc: func(t *testing.T, service map[string]interface{}) {
				// Check metadata
				metadata, ok := service["metadata"].(map[string]interface{})
				if !ok {
					t.Fatal("metadata not found")
				}
				if metadata["name"] != "test-app-sidecar" {
					t.Errorf("Expected name 'test-app-sidecar', got %v", metadata["name"])
				}
				if metadata["namespace"] != "default" {
					t.Errorf("Expected namespace 'default', got %v", metadata["namespace"])
				}

				// Check spec
				spec, ok := service["spec"].(map[string]interface{})
				if !ok {
					t.Fatal("spec not found")
				}

				// Check type
				if spec["type"] != "ClusterIP" {
					t.Errorf("Expected type 'ClusterIP', got %v", spec["type"])
				}

				// Check selector (should match pod labels)
				selector, ok := spec["selector"].(map[string]interface{})
				if !ok {
					t.Fatal("selector not found")
				}
				if selector["app"] != "test-app" {
					t.Errorf("Expected selector app='test-app', got %v", selector["app"])
				}
				if selector["version"] != "v1" {
					t.Errorf("Expected selector version='v1', got %v", selector["version"])
				}

				// Check ports
				ports, ok := spec["ports"].([]interface{})
				if !ok || len(ports) != 1 {
					t.Fatalf("Expected 1 port, got %v", ports)
				}

				port, ok := ports[0].(map[string]interface{})
				if !ok {
					t.Fatal("port is not a map")
				}
				if port["port"] != 8443 {
					t.Errorf("Expected port 8443, got %v", port["port"])
				}
				if port["targetPort"] != 8443 {
					t.Errorf("Expected targetPort 8443, got %v", port["targetPort"])
				}
				if port["name"] != "https" {
					t.Errorf("Expected port name 'https', got %v", port["name"])
				}
			},
		},
		{
			name: "pod without labels",
			manifest: `apiVersion: v1
kind: Pod
metadata:
  name: simple-pod
  namespace: test
spec:
  containers:
  - name: main
    image: nginx:latest`,
			cfg: &config.CocoConfig{
				Sidecar: config.SidecarConfig{
					Enabled:   true,
					HTTPSPort: 9443,
				},
			},
			appName:   "simple-pod",
			namespace: "test",
			checkFunc: func(t *testing.T, service map[string]interface{}) {
				// Check metadata
				metadata, ok := service["metadata"].(map[string]interface{})
				if !ok {
					t.Fatal("metadata not found")
				}
				if metadata["name"] != "simple-pod-sidecar" {
					t.Errorf("Expected name 'simple-pod-sidecar', got %v", metadata["name"])
				}

				// Check spec
				spec, ok := service["spec"].(map[string]interface{})
				if !ok {
					t.Fatal("spec not found")
				}

				// Check selector (should have default label)
				selector, ok := spec["selector"].(map[string]interface{})
				if !ok {
					t.Fatal("selector not found")
				}
				if selector["app"] != "simple-pod" {
					t.Errorf("Expected default selector app='simple-pod', got %v", selector["app"])
				}

				// Check ports
				ports, ok := spec["ports"].([]interface{})
				if !ok || len(ports) != 1 {
					t.Fatalf("Expected 1 port, got %v", ports)
				}

				port, ok := ports[0].(map[string]interface{})
				if !ok {
					t.Fatal("port is not a map")
				}
				if port["port"] != 9443 {
					t.Errorf("Expected port 9443, got %v", port["port"])
				}
			},
		},
		{
			name: "sidecar disabled",
			manifest: `apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-app
spec:
  template:
    spec:
      containers:
      - name: main
        image: nginx:latest`,
			cfg: &config.CocoConfig{
				Sidecar: config.SidecarConfig{
					Enabled: false,
				},
			},
			appName:   "test-app",
			namespace: "default",
			checkFunc: func(t *testing.T, service map[string]interface{}) {
				// Should return empty map when disabled
				if len(service) != 0 {
					t.Errorf("Expected empty service map when sidecar disabled, got %v", service)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a temporary manifest file
			tmpFile := t.TempDir() + "/manifest.yaml"
			if err := os.WriteFile(tmpFile, []byte(tt.manifest), 0600); err != nil {
				t.Fatalf("Failed to create temp manifest: %v", err)
			}

			m, err := manifest.Load(tmpFile)
			if err != nil {
				t.Fatalf("Failed to load manifest: %v", err)
			}

			service, err := GenerateService(m, tt.cfg, tt.appName, tt.namespace)
			if err != nil {
				t.Fatalf("GenerateService() error = %v", err)
			}

			if service == nil {
				t.Fatal("Expected service map (even if empty), got nil")
			}

			if tt.checkFunc != nil {
				tt.checkFunc(t, service)
			}
		})
	}
}
