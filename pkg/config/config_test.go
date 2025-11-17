package config

import (
	"testing"
)

func TestApplyDefaults(t *testing.T) {
	tests := []struct {
		name   string
		cfg    *CocoConfig
		check  func(*testing.T, *CocoConfig)
	}{
		{
			name: "empty sidecar config gets defaults",
			cfg: &CocoConfig{
				Sidecar: SidecarConfig{
					Enabled: true,
				},
			},
			check: func(t *testing.T, cfg *CocoConfig) {
				if cfg.Sidecar.Image != DefaultSidecarImage {
					t.Errorf("Expected default image %s, got %s", DefaultSidecarImage, cfg.Sidecar.Image)
				}
				if cfg.Sidecar.HTTPSPort != DefaultSidecarHTTPSPort {
					t.Errorf("Expected default HTTPS port %d, got %d", DefaultSidecarHTTPSPort, cfg.Sidecar.HTTPSPort)
				}
				if cfg.Sidecar.TLSCertURI != DefaultSidecarTLSCertURI {
					t.Errorf("Expected default TLS cert URI %s, got %s", DefaultSidecarTLSCertURI, cfg.Sidecar.TLSCertURI)
				}
				if cfg.Sidecar.TLSKeyURI != DefaultSidecarTLSKeyURI {
					t.Errorf("Expected default TLS key URI %s, got %s", DefaultSidecarTLSKeyURI, cfg.Sidecar.TLSKeyURI)
				}
				if cfg.Sidecar.ClientCAURI != DefaultSidecarClientCAURI {
					t.Errorf("Expected default client CA URI %s, got %s", DefaultSidecarClientCAURI, cfg.Sidecar.ClientCAURI)
				}
				if cfg.Sidecar.CPULimit != DefaultSidecarCPULimit {
					t.Errorf("Expected default CPU limit %s, got %s", DefaultSidecarCPULimit, cfg.Sidecar.CPULimit)
				}
				if cfg.Sidecar.MemoryLimit != DefaultSidecarMemLimit {
					t.Errorf("Expected default memory limit %s, got %s", DefaultSidecarMemLimit, cfg.Sidecar.MemoryLimit)
				}
				if cfg.Sidecar.CPURequest != DefaultSidecarCPURequest {
					t.Errorf("Expected default CPU request %s, got %s", DefaultSidecarCPURequest, cfg.Sidecar.CPURequest)
				}
				if cfg.Sidecar.MemoryRequest != DefaultSidecarMemRequest {
					t.Errorf("Expected default memory request %s, got %s", DefaultSidecarMemRequest, cfg.Sidecar.MemoryRequest)
				}
			},
		},
		{
			name: "custom values are preserved",
			cfg: &CocoConfig{
				Sidecar: SidecarConfig{
					Enabled:     true,
					Image:       "custom:v1",
					HTTPSPort:   9443,
					TLSCertURI:  "kbs:///custom/cert",
					TLSKeyURI:   "kbs:///custom/key",
					ClientCAURI: "kbs:///custom/ca",
					CPULimit:    "200m",
					MemoryLimit: "256Mi",
				},
			},
			check: func(t *testing.T, cfg *CocoConfig) {
				if cfg.Sidecar.Image != "custom:v1" {
					t.Errorf("Custom image was changed, got %s", cfg.Sidecar.Image)
				}
				if cfg.Sidecar.HTTPSPort != 9443 {
					t.Errorf("Custom HTTPS port was changed, got %d", cfg.Sidecar.HTTPSPort)
				}
				if cfg.Sidecar.TLSCertURI != "kbs:///custom/cert" {
					t.Errorf("Custom TLS cert URI was changed, got %s", cfg.Sidecar.TLSCertURI)
				}
				if cfg.Sidecar.TLSKeyURI != "kbs:///custom/key" {
					t.Errorf("Custom TLS key URI was changed, got %s", cfg.Sidecar.TLSKeyURI)
				}
				if cfg.Sidecar.ClientCAURI != "kbs:///custom/ca" {
					t.Errorf("Custom client CA URI was changed, got %s", cfg.Sidecar.ClientCAURI)
				}
				if cfg.Sidecar.CPULimit != "200m" {
					t.Errorf("Custom CPU limit was changed, got %s", cfg.Sidecar.CPULimit)
				}
				if cfg.Sidecar.MemoryLimit != "256Mi" {
					t.Errorf("Custom memory limit was changed, got %s", cfg.Sidecar.MemoryLimit)
				}
			},
		},
		{
			name: "partial custom values get defaults for missing",
			cfg: &CocoConfig{
				Sidecar: SidecarConfig{
					Enabled:    true,
					Image:      "custom:v1",
					TLSCertURI: "kbs:///custom/cert",
					// Other fields empty, should get defaults
				},
			},
			check: func(t *testing.T, cfg *CocoConfig) {
				if cfg.Sidecar.Image != "custom:v1" {
					t.Errorf("Custom image was changed, got %s", cfg.Sidecar.Image)
				}
				if cfg.Sidecar.TLSCertURI != "kbs:///custom/cert" {
					t.Errorf("Custom TLS cert URI was changed, got %s", cfg.Sidecar.TLSCertURI)
				}
				// These should get defaults
				if cfg.Sidecar.HTTPSPort != DefaultSidecarHTTPSPort {
					t.Errorf("Expected default HTTPS port, got %d", cfg.Sidecar.HTTPSPort)
				}
				if cfg.Sidecar.TLSKeyURI != DefaultSidecarTLSKeyURI {
					t.Errorf("Expected default TLS key URI, got %s", cfg.Sidecar.TLSKeyURI)
				}
				if cfg.Sidecar.ClientCAURI != DefaultSidecarClientCAURI {
					t.Errorf("Expected default client CA URI, got %s", cfg.Sidecar.ClientCAURI)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			applyDefaults(tt.cfg)
			tt.check(t, tt.cfg)
		})
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	// Check sidecar defaults
	if cfg.Sidecar.Image != DefaultSidecarImage {
		t.Errorf("DefaultConfig sidecar image = %s, want %s", cfg.Sidecar.Image, DefaultSidecarImage)
	}
	if cfg.Sidecar.HTTPSPort != DefaultSidecarHTTPSPort {
		t.Errorf("DefaultConfig HTTPS port = %d, want %d", cfg.Sidecar.HTTPSPort, DefaultSidecarHTTPSPort)
	}
	if cfg.Sidecar.TLSCertURI != DefaultSidecarTLSCertURI {
		t.Errorf("DefaultConfig TLS cert URI = %s, want %s", cfg.Sidecar.TLSCertURI, DefaultSidecarTLSCertURI)
	}
	if cfg.Sidecar.TLSKeyURI != DefaultSidecarTLSKeyURI {
		t.Errorf("DefaultConfig TLS key URI = %s, want %s", cfg.Sidecar.TLSKeyURI, DefaultSidecarTLSKeyURI)
	}
	if cfg.Sidecar.ClientCAURI != DefaultSidecarClientCAURI {
		t.Errorf("DefaultConfig client CA URI = %s, want %s", cfg.Sidecar.ClientCAURI, DefaultSidecarClientCAURI)
	}
	if cfg.Sidecar.Enabled != false {
		t.Errorf("DefaultConfig sidecar enabled = %v, want false", cfg.Sidecar.Enabled)
	}
}

func TestGetTrusteeNamespace(t *testing.T) {
	tests := []struct {
		name          string
		trusteeServer string
		wantNamespace string
	}{
		{
			name:          "in-cluster service URL with cluster.local",
			trusteeServer: "http://trustee-kbs.coco-test.svc.cluster.local:8080",
			wantNamespace: "coco-test",
		},
		{
			name:          "in-cluster service URL without port",
			trusteeServer: "http://trustee-kbs.production.svc.cluster.local",
			wantNamespace: "production",
		},
		{
			name:          "https URL",
			trusteeServer: "https://trustee-kbs.staging.svc.cluster.local:8443",
			wantNamespace: "staging",
		},
		{
			name:          "simplified service URL",
			trusteeServer: "http://trustee-kbs.default.svc",
			wantNamespace: "default",
		},
		{
			name:          "URL without protocol",
			trusteeServer: "trustee-kbs.custom-ns.svc.cluster.local:8080",
			wantNamespace: "custom-ns",
		},
		{
			name:          "external URL - should default to default",
			trusteeServer: "https://trustee.example.com:8080",
			wantNamespace: "default",
		},
		{
			name:          "IP address - should default to default",
			trusteeServer: "http://192.168.1.100:8080",
			wantNamespace: "default",
		},
		{
			name:          "localhost - should default to default",
			trusteeServer: "http://localhost:8080",
			wantNamespace: "default",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &CocoConfig{
				TrusteeServer: tt.trusteeServer,
			}
			got := cfg.GetTrusteeNamespace()
			if got != tt.wantNamespace {
				t.Errorf("GetTrusteeNamespace() = %v, want %v", got, tt.wantNamespace)
			}
		})
	}
}
