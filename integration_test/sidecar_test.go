package integration_test

import (
	"testing"

	"github.com/confidential-devhub/cococtl/pkg/config"
	"github.com/confidential-devhub/cococtl/pkg/manifest"
	"github.com/confidential-devhub/cococtl/pkg/sidecar"
)

func TestSidecarInject_Pod(t *testing.T) {
	m, err := manifest.Load("testdata/manifests/simple-pod.yaml")
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	cfg := &config.CocoConfig{
		Sidecar: config.SidecarConfig{
			Enabled:     true,
			Image:       "test-sidecar:latest",
			HTTPSPort:   8443,
			CPULimit:    "100m",
			MemoryLimit: "128Mi",
		},
	}

	err = sidecar.Inject(m, cfg, "test-app", "default")
	if err != nil {
		t.Fatalf("Inject() failed: %v", err)
	}

	// Verify sidecar was added
	podSpec, err := m.GetPodSpec()
	if err != nil {
		t.Fatalf("GetPodSpec() failed: %v", err)
	}

	containers, ok := podSpec["containers"].([]interface{})
	if !ok {
		t.Fatal("containers is not a slice")
	}

	// Should have original container + sidecar
	if len(containers) != 2 {
		t.Errorf("Expected 2 containers, got %d", len(containers))
	}

	// Verify sidecar container exists
	sidecarFound := false
	for _, c := range containers {
		container, ok := c.(map[string]interface{})
		if !ok {
			continue
		}
		if container["name"] == "coco-secure-access" {
			sidecarFound = true

			// Verify image
			if container["image"] != "test-sidecar:latest" {
				t.Errorf("Expected sidecar image 'test-sidecar:latest', got %v", container["image"])
			}

			// Verify ports
			ports, ok := container["ports"].([]interface{})
			if !ok || len(ports) != 1 {
				t.Errorf("Expected 1 port in sidecar, got %v", ports)
			}

			// Verify environment variables
			env, ok := container["env"].([]interface{})
			if !ok || len(env) < 5 {
				t.Errorf("Expected at least 5 env vars in sidecar, got %v", len(env))
			}

			break
		}
	}

	if !sidecarFound {
		t.Error("Sidecar container not found in manifest")
	}
}

func TestSidecarInject_Deployment(t *testing.T) {
	m, err := manifest.Load("testdata/manifests/deployment.yaml")
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	cfg := &config.CocoConfig{
		Sidecar: config.SidecarConfig{
			Enabled:   true,
			Image:     "test-sidecar:latest",
			HTTPSPort: 8443,
		},
	}

	err = sidecar.Inject(m, cfg, "test-deployment", "default")
	if err != nil {
		t.Fatalf("Inject() failed: %v", err)
	}

	// Verify sidecar was added to deployment
	podSpec, err := m.GetPodSpec()
	if err != nil {
		t.Fatalf("GetPodSpec() failed: %v", err)
	}

	containers, ok := podSpec["containers"].([]interface{})
	if !ok {
		t.Fatal("containers is not a slice")
	}

	// Should have original container + sidecar
	if len(containers) != 2 {
		t.Errorf("Expected 2 containers in deployment, got %d", len(containers))
	}

	// Verify sidecar exists
	sidecarFound := false
	for _, c := range containers {
		container, ok := c.(map[string]interface{})
		if !ok {
			continue
		}
		if container["name"] == "coco-secure-access" {
			sidecarFound = true
			break
		}
	}

	if !sidecarFound {
		t.Error("Sidecar container not found in deployment manifest")
	}
}


func TestSidecarInject_WithForwardPort(t *testing.T) {
	m, err := manifest.Load("testdata/manifests/simple-pod.yaml")
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	cfg := &config.CocoConfig{
		Sidecar: config.SidecarConfig{
			Enabled:      true,
			Image:        "test-sidecar:latest",
			HTTPSPort:    8443,
			ForwardPort: 8888,
		},
	}

	err = sidecar.Inject(m, cfg, "test-app", "default")
	if err != nil {
		t.Fatalf("Inject() failed: %v", err)
	}

	// Verify FORWARD_PORT env var is present
	podSpec, err := m.GetPodSpec()
	if err != nil {
		t.Fatalf("GetPodSpec() failed: %v", err)
	}

	containers, ok := podSpec["containers"].([]interface{})
	if !ok {
		t.Fatal("containers is not a slice")
	}

	for _, c := range containers {
		container, ok := c.(map[string]interface{})
		if !ok || container["name"] != "coco-secure-access" {
			continue
		}

		env, ok := container["env"].([]interface{})
		if !ok {
			t.Fatal("env is not a slice")
		}

		forwardPortsFound := false
		for _, e := range env {
			envVar, ok := e.(map[string]interface{})
			if !ok {
				continue
			}
			if envVar["name"] == "FORWARD_PORT" {
				forwardPortsFound = true
				if envVar["value"] != "8888" {
					t.Errorf("Expected FORWARD_PORT value '8888', got %v", envVar["value"])
				}
				break
			}
		}

		if !forwardPortsFound {
			t.Error("FORWARD_PORT not found in sidecar environment variables")
		}
	}
}

func TestSidecarInject_Disabled(t *testing.T) {
	m, err := manifest.Load("testdata/manifests/simple-pod.yaml")
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// Get original container count
	podSpecBefore, err := m.GetPodSpec()
	if err != nil {
		t.Fatalf("GetPodSpec() failed: %v", err)
	}
	containersBefore, _ := podSpecBefore["containers"].([]interface{})
	countBefore := len(containersBefore)

	cfg := &config.CocoConfig{
		Sidecar: config.SidecarConfig{
			Enabled: false, // Disabled
		},
	}

	err = sidecar.Inject(m, cfg, "test-app", "default")
	if err != nil {
		t.Fatalf("Inject() failed: %v", err)
	}

	// Verify sidecar was NOT added
	podSpecAfter, err := m.GetPodSpec()
	if err != nil {
		t.Fatalf("GetPodSpec() failed: %v", err)
	}

	containersAfter, ok := podSpecAfter["containers"].([]interface{})
	if !ok {
		t.Fatal("containers is not a slice")
	}

	// Container count should be the same
	if len(containersAfter) != countBefore {
		t.Errorf("Expected %d containers (no sidecar), got %d", countBefore, len(containersAfter))
	}
}

func TestSidecarInject_InvalidConfig(t *testing.T) {
	m, err := manifest.Load("testdata/manifests/simple-pod.yaml")
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	tests := []struct {
		name string
		cfg  *config.CocoConfig
	}{
		{
			name: "missing image",
			cfg: &config.CocoConfig{
				Sidecar: config.SidecarConfig{
					Enabled:   true,
					HTTPSPort: 8443,
				},
			},
		},
		{
			name: "invalid https_port - zero",
			cfg: &config.CocoConfig{
				Sidecar: config.SidecarConfig{
					Enabled:   true,
					Image:     "test:latest",
					HTTPSPort: 0,
				},
			},
		},
		{
			name: "invalid https_port - too high",
			cfg: &config.CocoConfig{
				Sidecar: config.SidecarConfig{
					Enabled:   true,
					Image:     "test:latest",
					HTTPSPort: 70000,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := sidecar.Inject(m, tt.cfg, "test-app", "default")
			if err == nil {
				t.Error("Expected error for invalid config, got nil")
			}
		})
	}
}
