package integration_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-devhub/cococtl/pkg/sidecar"
	"github.com/confidential-devhub/cococtl/pkg/sidecar/certs"
)

func TestCertificateGeneration_CA(t *testing.T) {
	ca, err := certs.GenerateCA("Test CA")
	if err != nil {
		t.Fatalf("GenerateCA() failed: %v", err)
	}

	if len(ca.CertPEM) == 0 {
		t.Error("Generated CA certificate PEM is empty")
	}

	if len(ca.KeyPEM) == 0 {
		t.Error("Generated CA key PEM is empty")
	}

	// Verify PEM format
	if !strings.Contains(string(ca.CertPEM), "BEGIN CERTIFICATE") {
		t.Error("CA certificate PEM does not contain BEGIN CERTIFICATE")
	}
	if !strings.Contains(string(ca.KeyPEM), "BEGIN RSA PRIVATE KEY") {
		t.Error("CA key PEM does not contain BEGIN RSA PRIVATE KEY")
	}
}

func TestCertificateGeneration_ServerCert(t *testing.T) {
	// Generate CA first
	ca, err := certs.GenerateCA("Test CA")
	if err != nil {
		t.Fatalf("GenerateCA() failed: %v", err)
	}

	// Generate server certificate with SANs
	sans := certs.SANs{
		DNSNames:    []string{"example.com", "*.example.com"},
		IPAddresses: []string{"192.168.1.1", "10.0.0.1"},
	}

	serverCert, err := certs.GenerateServerCert(ca.CertPEM, ca.KeyPEM, "test-server", sans)
	if err != nil {
		t.Fatalf("GenerateServerCert() failed: %v", err)
	}

	if len(serverCert.CertPEM) == 0 {
		t.Error("Generated server certificate PEM is empty")
	}

	if len(serverCert.KeyPEM) == 0 {
		t.Error("Generated server key PEM is empty")
	}

	// Verify PEM format
	if !strings.Contains(string(serverCert.CertPEM), "BEGIN CERTIFICATE") {
		t.Error("Server certificate PEM does not contain BEGIN CERTIFICATE")
	}
	if !strings.Contains(string(serverCert.KeyPEM), "BEGIN RSA PRIVATE KEY") {
		t.Error("Server key PEM does not contain BEGIN RSA PRIVATE KEY")
	}
}

func TestCertificateGeneration_ClientCert(t *testing.T) {
	// Generate CA first
	ca, err := certs.GenerateCA("Test CA")
	if err != nil {
		t.Fatalf("GenerateCA() failed: %v", err)
	}

	// Generate client certificate
	clientCert, err := certs.GenerateClientCert(ca.CertPEM, ca.KeyPEM, "test-client")
	if err != nil {
		t.Fatalf("GenerateClientCert() failed: %v", err)
	}

	if len(clientCert.CertPEM) == 0 {
		t.Error("Generated client certificate PEM is empty")
	}

	if len(clientCert.KeyPEM) == 0 {
		t.Error("Generated client key PEM is empty")
	}

	// Verify PEM format
	if !strings.Contains(string(clientCert.CertPEM), "BEGIN CERTIFICATE") {
		t.Error("Client certificate PEM does not contain BEGIN CERTIFICATE")
	}
	if !strings.Contains(string(clientCert.KeyPEM), "BEGIN RSA PRIVATE KEY") {
		t.Error("Client key PEM does not contain BEGIN RSA PRIVATE KEY")
	}
}

func TestCertificateSaveToFile(t *testing.T) {
	// Generate CA
	ca, err := certs.GenerateCA("Test CA")
	if err != nil {
		t.Fatalf("GenerateCA() failed: %v", err)
	}

	// Create temporary directory
	tmpDir := t.TempDir()

	// Save to file
	if err := ca.SaveToFile(tmpDir, "test-ca"); err != nil {
		t.Fatalf("SaveToFile() failed: %v", err)
	}

	// Verify files exist
	certPath := filepath.Join(tmpDir, "test-ca-cert.pem")
	keyPath := filepath.Join(tmpDir, "test-ca-key.pem")

	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		t.Errorf("Certificate file not created: %s", certPath)
	}

	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Errorf("Key file not created: %s", keyPath)
	}

	// Verify file contents
	certData, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("Failed to read certificate file: %v", err)
	}

	if !strings.Contains(string(certData), "BEGIN CERTIFICATE") {
		t.Error("Saved certificate file does not contain valid PEM data")
	}

	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("Failed to read key file: %v", err)
	}

	if !strings.Contains(string(keyData), "BEGIN RSA PRIVATE KEY") {
		t.Error("Saved key file does not contain valid PEM data")
	}
}

func TestGenerateCertURIs(t *testing.T) {
	tests := []struct {
		name               string
		appName            string
		namespace          string
		expectedServerCert string
		expectedServerKey  string
		expectedClientCA   string
	}{
		{
			name:               "default namespace",
			appName:            "my-app",
			namespace:          "default",
			expectedServerCert: "kbs:///default/sidecar-tls-my-app/server-cert",
			expectedServerKey:  "kbs:///default/sidecar-tls-my-app/server-key",
			expectedClientCA:   "kbs:///default/sidecar-tls/client-ca",
		},
		{
			name:               "custom namespace",
			appName:            "web-server",
			namespace:          "production",
			expectedServerCert: "kbs:///production/sidecar-tls-web-server/server-cert",
			expectedServerKey:  "kbs:///production/sidecar-tls-web-server/server-key",
			expectedClientCA:   "kbs:///default/sidecar-tls/client-ca",
		},
		{
			name:               "app with hyphens",
			appName:            "my-cool-app",
			namespace:          "staging",
			expectedServerCert: "kbs:///staging/sidecar-tls-my-cool-app/server-cert",
			expectedServerKey:  "kbs:///staging/sidecar-tls-my-cool-app/server-key",
			expectedClientCA:   "kbs:///default/sidecar-tls/client-ca",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serverCertURI, serverKeyURI, clientCAURI := sidecar.GenerateCertURIs(tt.appName, tt.namespace)

			if serverCertURI != tt.expectedServerCert {
				t.Errorf("serverCertURI = %s, want %s", serverCertURI, tt.expectedServerCert)
			}

			if serverKeyURI != tt.expectedServerKey {
				t.Errorf("serverKeyURI = %s, want %s", serverKeyURI, tt.expectedServerKey)
			}

			if clientCAURI != tt.expectedClientCA {
				t.Errorf("clientCAURI = %s, want %s", clientCAURI, tt.expectedClientCA)
			}
		})
	}
}

func TestServerCertWithMultipleSANs(t *testing.T) {
	// Generate CA
	ca, err := certs.GenerateCA("Test CA")
	if err != nil {
		t.Fatalf("GenerateCA() failed: %v", err)
	}

	// Generate server certificate with multiple SANs
	sans := certs.SANs{
		DNSNames: []string{
			"service.default.svc.cluster.local",
			"service.default.svc",
			"service",
		},
		IPAddresses: []string{
			"10.96.0.1",
			"192.168.1.100",
			"172.16.0.50",
		},
	}

	serverCert, err := certs.GenerateServerCert(ca.CertPEM, ca.KeyPEM, "test-server", sans)
	if err != nil {
		t.Fatalf("GenerateServerCert() with multiple SANs failed: %v", err)
	}

	if len(serverCert.CertPEM) == 0 {
		t.Error("Generated server certificate with multiple SANs is empty")
	}
}

func TestServerCertWithInvalidIP(t *testing.T) {
	// Generate CA
	ca, err := certs.GenerateCA("Test CA")
	if err != nil {
		t.Fatalf("GenerateCA() failed: %v", err)
	}

	// Try to generate server certificate with invalid IP
	sans := certs.SANs{
		DNSNames:    []string{"example.com"},
		IPAddresses: []string{"invalid-ip"},
	}

	_, err = certs.GenerateServerCert(ca.CertPEM, ca.KeyPEM, "test-server", sans)
	if err == nil {
		t.Error("Expected error for invalid IP address, got nil")
	}
}

func TestCertificateChain(t *testing.T) {
	// Test that we can generate a complete certificate chain:
	// CA -> Server Cert and CA -> Client Cert

	// 1. Generate CA
	ca, err := certs.GenerateCA("Test Root CA")
	if err != nil {
		t.Fatalf("GenerateCA() failed: %v", err)
	}

	// 2. Generate server certificate
	serverSANs := certs.SANs{
		DNSNames:    []string{"server.example.com"},
		IPAddresses: []string{"192.168.1.1"},
	}
	serverCert, err := certs.GenerateServerCert(ca.CertPEM, ca.KeyPEM, "test-server", serverSANs)
	if err != nil {
		t.Fatalf("GenerateServerCert() failed: %v", err)
	}

	// 3. Generate client certificate
	clientCert, err := certs.GenerateClientCert(ca.CertPEM, ca.KeyPEM, "test-client")
	if err != nil {
		t.Fatalf("GenerateClientCert() failed: %v", err)
	}

	// Verify all certificates are valid PEM
	certs := []struct {
		name     string
		certPEM  []byte
		keyPEM   []byte
	}{
		{"CA", ca.CertPEM, ca.KeyPEM},
		{"Server", serverCert.CertPEM, serverCert.KeyPEM},
		{"Client", clientCert.CertPEM, clientCert.KeyPEM},
	}

	for _, c := range certs {
		if !strings.Contains(string(c.certPEM), "BEGIN CERTIFICATE") {
			t.Errorf("%s certificate PEM is invalid", c.name)
		}
		if !strings.Contains(string(c.keyPEM), "BEGIN RSA PRIVATE KEY") {
			t.Errorf("%s key PEM is invalid", c.name)
		}
	}
}
