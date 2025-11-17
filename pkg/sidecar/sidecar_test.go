package sidecar

import (
	"testing"

	"github.com/confidential-devhub/cococtl/pkg/config"
)

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *config.CocoConfig
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid config",
			cfg: &config.CocoConfig{
				Sidecar: config.SidecarConfig{
					Enabled:   true,
					Image:     "test:latest",
					HTTPSPort: 8443,
				},
			},
			wantErr: false,
		},
		{
			name: "missing image",
			cfg: &config.CocoConfig{
				Sidecar: config.SidecarConfig{
					Enabled:   true,
					HTTPSPort: 8443,
				},
			},
			wantErr: true,
			errMsg:  "sidecar image is required",
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
			wantErr: true,
			errMsg:  "invalid https_port",
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
			wantErr: true,
			errMsg:  "invalid https_port",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateConfig(tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && err != nil {
				if tt.errMsg != "" && err.Error() != tt.errMsg {
					// Check if error contains expected message
					if len(err.Error()) < len(tt.errMsg) || err.Error()[:len(tt.errMsg)] != tt.errMsg {
						t.Errorf("validateConfig() error = %v, want error containing %v", err, tt.errMsg)
					}
				}
			}
		})
	}
}

func TestBuildContainer(t *testing.T) {
	tests := []struct {
		name      string
		cfg       *config.CocoConfig
		checkFunc func(t *testing.T, container map[string]interface{})
	}{
		{
			name: "basic container",
			cfg: &config.CocoConfig{
				Sidecar: config.SidecarConfig{
					Image:     "test:latest",
					HTTPSPort: 8443,
				},
			},
			checkFunc: func(t *testing.T, container map[string]interface{}) {
				if container["name"] != "coco-secure-access" {
					t.Errorf("Expected name 'coco-secure-access', got %v", container["name"])
				}
				if container["image"] != "test:latest" {
					t.Errorf("Expected image 'test:latest', got %v", container["image"])
				}

				// Check ports
				ports, ok := container["ports"].([]interface{})
				if !ok || len(ports) != 1 {
					t.Errorf("Expected 1 port, got %v", ports)
				}

				// Check environment variables
				env, ok := container["env"].([]interface{})
				if !ok || len(env) < 5 {
					t.Errorf("Expected at least 5 env vars, got %v", len(env))
				}
			},
		},
		{
			name: "with forward port",
			cfg: &config.CocoConfig{
				Sidecar: config.SidecarConfig{
					Image:       "test:latest",
					HTTPSPort:   8443,
					ForwardPort: 8888,
				},
			},
			checkFunc: func(t *testing.T, container map[string]interface{}) {
				env, ok := container["env"].([]interface{})
				if !ok {
					t.Fatal("env is not a slice")
				}

				// Check for FORWARD_PORT
				found := false
				for _, e := range env {
					envVar, ok := e.(map[string]interface{})
					if !ok {
						continue
					}
					if envVar["name"] == "FORWARD_PORT" {
						found = true
						if envVar["value"] != "8888" {
							t.Errorf("Expected FORWARD_PORT value '8888', got %v", envVar["value"])
						}
					}
				}
				if !found {
					t.Error("FORWARD_PORT not found in env vars")
				}
			},
		},
		{
			name: "with resource limits and requests",
			cfg: &config.CocoConfig{
				Sidecar: config.SidecarConfig{
					Image:         "test:latest",
					HTTPSPort:     8443,
					CPULimit:      "100m",
					MemoryLimit:   "128Mi",
					CPURequest:    "50m",
					MemoryRequest: "64Mi",
				},
			},
			checkFunc: func(t *testing.T, container map[string]interface{}) {
				resources, ok := container["resources"].(map[string]interface{})
				if !ok {
					t.Fatal("resources not found")
				}

				limits, ok := resources["limits"].(map[string]interface{})
				if !ok {
					t.Fatal("limits not found")
				}
				if limits["cpu"] != "100m" {
					t.Errorf("Expected cpu limit '100m', got %v", limits["cpu"])
				}
				if limits["memory"] != "128Mi" {
					t.Errorf("Expected memory limit '128Mi', got %v", limits["memory"])
				}

				requests, ok := resources["requests"].(map[string]interface{})
				if !ok {
					t.Fatal("requests not found")
				}
				if requests["cpu"] != "50m" {
					t.Errorf("Expected cpu request '50m', got %v", requests["cpu"])
				}
				if requests["memory"] != "64Mi" {
					t.Errorf("Expected memory request '64Mi', got %v", requests["memory"])
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			container := buildContainer(tt.cfg, "test-app", "default")
			tt.checkFunc(t, container)
		})
	}
}
