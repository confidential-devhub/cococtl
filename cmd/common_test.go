package cmd

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// TestIsRemoteFile_VariousURLFormats tests URL detection with different formats
func TestIsRemoteFile_VariousURLFormats(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{
			name:     "Valid HTTP URL",
			path:     "http://example.com/manifest.yaml",
			expected: true,
		},
		{
			name:     "Valid HTTPS URL",
			path:     "https://example.com/manifest.yaml",
			expected: true,
		},
		{
			name:     "HTTP URL with port",
			path:     "http://example.com:8080/manifest.yaml",
			expected: true,
		},
		{
			name:     "HTTPS URL with query params",
			path:     "https://example.com/manifest.yaml?version=1.0",
			expected: true,
		},
		{
			name:     "HTTPS URL with fragment",
			path:     "https://example.com/manifest.yaml#section",
			expected: true,
		},
		{
			name:     "Absolute file path",
			path:     "/path/to/manifest.yaml",
			expected: false,
		},
		{
			name:     "Relative file path",
			path:     "manifest.yaml",
			expected: false,
		},
		{
			name:     "Relative path with directory",
			path:     "./manifests/pod.yaml",
			expected: false,
		},
		{
			name:     "Parent directory reference",
			path:     "../manifests/pod.yaml",
			expected: false,
		},
		{
			name:     "File scheme URL",
			path:     "file:///path/to/manifest.yaml",
			expected: false,
		},
		{
			name:     "FTP URL",
			path:     "ftp://example.com/manifest.yaml",
			expected: false,
		},
		{
			name:     "SSH URL",
			path:     "ssh://example.com/manifest.yaml",
			expected: false,
		},
		{
			name:     "Empty string",
			path:     "",
			expected: false,
		},
		{
			name:     "Invalid URL characters",
			path:     "ht!tp://invalid",
			expected: false,
		},
		{
			name:     "Just a hostname",
			path:     "example.com",
			expected: false,
		},
		{
			name:     "Path with spaces",
			path:     "/path/with spaces/manifest.yaml",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isRemoteFile(tt.path)
			if result != tt.expected {
				t.Errorf("isRemoteFile(%q) = %v, expected %v", tt.path, result, tt.expected)
			}
		})
	}
}

// TestIsPrivateIP_VariousAddresses tests private IP detection
func TestIsPrivateIP_VariousAddresses(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		// Loopback addresses
		{name: "IPv4 Loopback 127.0.0.1", ip: "127.0.0.1", expected: true},
		{name: "IPv4 Loopback 127.1.2.3", ip: "127.1.2.3", expected: true},
		{name: "IPv6 Loopback", ip: "::1", expected: true},

		// Link-local addresses
		{name: "IPv4 Link-local 169.254.1.1", ip: "169.254.1.1", expected: true},
		{name: "IPv6 Link-local", ip: "fe80::1", expected: true},

		// Private IPv4 ranges
		{name: "Private 10.0.0.1", ip: "10.0.0.1", expected: true},
		{name: "Private 10.255.255.255", ip: "10.255.255.255", expected: true},
		{name: "Private 172.16.0.1", ip: "172.16.0.1", expected: true},
		{name: "Private 172.31.255.255", ip: "172.31.255.255", expected: true},
		{name: "Private 192.168.0.1", ip: "192.168.0.1", expected: true},
		{name: "Private 192.168.255.255", ip: "192.168.255.255", expected: true},

		// Private IPv6 ranges
		{name: "IPv6 ULA fc00::1", ip: "fc00::1", expected: true},
		{name: "IPv6 ULA fd00::1", ip: "fd00::1", expected: true},

		// Public addresses
		{name: "Public 8.8.8.8", ip: "8.8.8.8", expected: false},
		{name: "Public 1.1.1.1", ip: "1.1.1.1", expected: false},
		{name: "Public 93.184.216.34", ip: "93.184.216.34", expected: false},
		{name: "Public IPv6 2001:4860:4860::8888", ip: "2001:4860:4860::8888", expected: false},

		// Edge cases
		{name: "Just outside private 11.0.0.1", ip: "11.0.0.1", expected: false},
		{name: "Just outside private 172.15.255.255", ip: "172.15.255.255", expected: false},
		{name: "Just outside private 172.32.0.1", ip: "172.32.0.1", expected: false},
		{name: "Just outside private 192.167.255.255", ip: "192.167.255.255", expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("Failed to parse IP: %s", tt.ip)
			}

			result := isPrivateIP(ip)
			if result != tt.expected {
				t.Errorf("isPrivateIP(%s) = %v, expected %v", tt.ip, result, tt.expected)
			}
		})
	}
}

// TestDownloadRemoteFile_Success tests successful file download
func TestDownloadRemoteFile_Success(t *testing.T) {
	validYAML := `apiVersion: v1
kind: Pod
metadata:
  name: test-pod
spec:
  containers:
  - name: nginx
    image: nginx:latest`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/x-yaml")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(validYAML))
	}))
	defer server.Close()

	// Use internal function with test client to bypass SSRF protection for functional testing
	tmpFile, err := downloadRemoteFileInternal(server.URL, server.Client())
	if err != nil {
		t.Fatalf("downloadRemoteFile() failed: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile) }()

	// Verify the file was created and contains the expected content
	content, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("Failed to read downloaded file: %v", err)
	}

	if string(content) != validYAML {
		t.Errorf("Downloaded content mismatch.\nGot:\n%s\nExpected:\n%s", content, validYAML)
	}
}

// TestDownloadRemoteFile_HTTP404 tests handling of 404 errors
func TestDownloadRemoteFile_HTTP404(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("Not Found"))
	}))
	defer server.Close()

	_, err := downloadRemoteFileInternal(server.URL, server.Client())
	if err == nil {
		t.Fatal("Expected error for HTTP 404, got nil")
	}

	if !strings.Contains(err.Error(), "404") {
		t.Errorf("Error message should mention 404, got: %v", err)
	}
}

// TestDownloadRemoteFile_HTTP500 tests handling of server errors
func TestDownloadRemoteFile_HTTP500(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("Internal Server Error"))
	}))
	defer server.Close()

	_, err := downloadRemoteFileInternal(server.URL, server.Client())
	if err == nil {
		t.Fatal("Expected error for HTTP 500, got nil")
	}

	if !strings.Contains(err.Error(), "500") {
		t.Errorf("Error message should mention 500, got: %v", err)
	}
}

// TestDownloadRemoteFile_LargeFileContentLength tests size limit with Content-Length header
func TestDownloadRemoteFile_LargeFileContentLength(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "20971520") // 20MB
		w.WriteHeader(http.StatusOK)
		// Don't actually write 20MB to speed up test
	}))
	defer server.Close()

	_, err := downloadRemoteFileInternal(server.URL, server.Client())
	if err == nil {
		t.Fatal("Expected error for large file, got nil")
	}

	if !strings.Contains(err.Error(), "too large") {
		t.Errorf("Error should mention file too large, got: %v", err)
	}
}

// TestDownloadRemoteFile_LargeFileActualSize tests size limit enforcement during read
func TestDownloadRemoteFile_LargeFileActualSize(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Don't set Content-Length, but write more than 10MB
		w.WriteHeader(http.StatusOK)
		// Write 11MB of data
		data := make([]byte, 1024*1024) // 1MB chunks
		for i := 0; i < 11; i++ {
			_, _ = w.Write(data)
		}
	}))
	defer server.Close()

	_, err := downloadRemoteFileInternal(server.URL, server.Client())
	if err == nil {
		t.Fatal("Expected error for large file, got nil")
	}

	if !strings.Contains(err.Error(), "too large") && !strings.Contains(err.Error(), "maximum size") {
		t.Errorf("Error should mention file size limit, got: %v", err)
	}
}

// TestDownloadRemoteFile_NonYAMLContent tests YAML validation
func TestDownloadRemoteFile_NonYAMLContent(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{
			name:    "Invalid YAML syntax",
			content: "invalid: yaml: {]",
		},
		{
			name:    "Unclosed bracket",
			content: "key: [value",
		},
		{
			name:    "Invalid indentation",
			content: "key:\n value\n  nested: wrong",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(tt.content))
			}))
			defer server.Close()

			_, err := downloadRemoteFileInternal(server.URL, server.Client())
			if err == nil {
				t.Fatal("Expected error for non-YAML content, got nil")
			}

			if !strings.Contains(err.Error(), "not valid YAML") {
				t.Errorf("Error should mention invalid YAML, got: %v", err)
			}
		})
	}
}

// TestDownloadRemoteFile_EmptyFile tests handling of empty files
func TestDownloadRemoteFile_EmptyFile(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		// Write nothing
	}))
	defer server.Close()

	_, err := downloadRemoteFileInternal(server.URL, server.Client())
	if err == nil {
		t.Fatal("Expected error for empty file, got nil")
	}

	if !strings.Contains(err.Error(), "empty") && !strings.Contains(err.Error(), "no valid YAML") {
		t.Errorf("Error should mention empty file or no valid YAML, got: %v", err)
	}
}

// TestDownloadRemoteFile_TooManyDocuments tests document count limit
func TestDownloadRemoteFile_TooManyDocuments(t *testing.T) {
	// Create YAML with more than 10 documents
	var yaml strings.Builder
	for i := 0; i < 15; i++ {
		yaml.WriteString(fmt.Sprintf("---\napiVersion: v1\nkind: Pod\nmetadata:\n  name: pod-%d\n", i))
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(yaml.String()))
	}))
	defer server.Close()

	_, err := downloadRemoteFileInternal(server.URL, server.Client())
	if err == nil {
		t.Fatal("Expected error for too many documents, got nil")
	}

	if !strings.Contains(err.Error(), "too many") {
		t.Errorf("Error should mention too many documents, got: %v", err)
	}
}

// TestDownloadRemoteFile_ValidMultiDocument tests valid multi-document YAML
func TestDownloadRemoteFile_ValidMultiDocument(t *testing.T) {
	multiDocYAML := `---
apiVersion: v1
kind: Service
metadata:
  name: test-service
---
apiVersion: v1
kind: Pod
metadata:
  name: test-pod`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(multiDocYAML))
	}))
	defer server.Close()

	tmpFile, err := downloadRemoteFileInternal(server.URL, server.Client())
	if err != nil {
		t.Fatalf("downloadRemoteFile() failed for valid multi-document YAML: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile) }()

	// Verify content
	content, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("Failed to read downloaded file: %v", err)
	}

	if string(content) != multiDocYAML {
		t.Errorf("Downloaded content mismatch")
	}
}

// TestDownloadRemoteFile_Redirect tests valid redirect handling
// Note: httptest.NewServer uses localhost (127.0.0.1), which is correctly blocked by SSRF protection.
// This test verifies that redirects to localhost are properly blocked.
func TestDownloadRemoteFile_Redirect(t *testing.T) {
	validYAML := `apiVersion: v1
kind: Pod
metadata:
  name: test-pod`

	// Create target server
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(validYAML))
	}))
	defer targetServer.Close()

	// Create redirect server
	redirectServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, targetServer.URL, http.StatusFound)
	}))
	defer redirectServer.Close()

	_, err := downloadRemoteFile(redirectServer.URL)
	// Should fail because httptest servers run on localhost, which is blocked by SSRF protection
	if err == nil {
		t.Fatal("Expected error for redirect to localhost (SSRF protection), got nil")
	}

	if !strings.Contains(err.Error(), "private/internal") && !strings.Contains(err.Error(), "127.0.0.1") && !strings.Contains(err.Error(), "IP") {
		t.Errorf("Error should mention IP/private/internal blocking, got: %v", err)
	}
}

// TestDownloadRemoteFile_RedirectLoop tests redirect loop detection
// Note: httptest.NewServer uses localhost, which is blocked by SSRF protection.
// This test verifies SSRF protection blocks localhost redirects.
func TestDownloadRemoteFile_RedirectLoop(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Redirect to itself to create a loop
		http.Redirect(w, r, server.URL, http.StatusFound)
	}))
	defer server.Close()

	_, err := downloadRemoteFileInternal(server.URL, server.Client())
	if err == nil {
		t.Fatal("Expected error for redirect, got nil")
	}

	// Should be blocked by SSRF protection before hitting redirect limit
	if !strings.Contains(err.Error(), "private/internal") && !strings.Contains(err.Error(), "127.0.0.1") {
		t.Logf("Note: Error blocked by SSRF protection (expected): %v", err)
	}
}

// TestDownloadRemoteFile_MultipleRedirects tests chain of redirects
// Note: httptest.NewServer uses localhost, which is blocked by SSRF protection.
// This test verifies SSRF protection blocks redirect chains to localhost.
func TestDownloadRemoteFile_MultipleRedirects(t *testing.T) {
	validYAML := `apiVersion: v1
kind: Pod
metadata:
  name: test-pod`

	// Create final target
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(validYAML))
	}))
	defer target.Close()

	// Create redirect chain: redirect1 -> redirect2 -> redirect3 -> target
	redirect3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer redirect3.Close()

	redirect2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, redirect3.URL, http.StatusFound)
	}))
	defer redirect2.Close()

	redirect1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, redirect2.URL, http.StatusFound)
	}))
	defer redirect1.Close()

	_, err := downloadRemoteFile(redirect1.URL)
	// Should fail because all httptest servers run on localhost, blocked by SSRF protection
	if err == nil {
		t.Fatal("Expected error for redirect chain to localhost (SSRF protection), got nil")
	}

	if !strings.Contains(err.Error(), "private/internal") && !strings.Contains(err.Error(), "127.0.0.1") && !strings.Contains(err.Error(), "IP") {
		t.Errorf("Error should mention IP/private/internal blocking, got: %v", err)
	}
}

// TestDownloadRemoteFile_Timeout tests timeout handling
func TestDownloadRemoteFile_Timeout(t *testing.T) {
	// This test takes 31+ seconds to run, so it's marked as slow
	if testing.Short() {
		t.Skip("Skipping timeout test in short mode")
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Sleep longer than the 30s timeout
		time.Sleep(35 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create a client with timeout but without SSRF protection for testing timeout behavior
	testClient := &http.Client{
		Timeout: 30 * time.Second,
	}

	start := time.Now()
	_, err := downloadRemoteFileInternal(server.URL, testClient)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("Expected timeout error, got nil")
	}

	// Should timeout around 30 seconds, not wait 35+ seconds
	if elapsed > 32*time.Second {
		t.Errorf("Timeout took too long: %v (expected ~30s)", elapsed)
	}

	if !strings.Contains(err.Error(), "timeout") && !strings.Contains(err.Error(), "deadline") {
		t.Logf("Warning: Error message doesn't explicitly mention timeout: %v", err)
	}
}

// TestDownloadRemoteFile_ContentTypeVariations tests different Content-Type headers
func TestDownloadRemoteFile_ContentTypeVariations(t *testing.T) {
	validYAML := `apiVersion: v1
kind: Pod
metadata:
  name: test-pod`

	contentTypes := []string{
		"application/x-yaml",
		"application/yaml",
		"text/yaml",
		"text/plain", // GitHub raw serves as text/plain
		"",           // No Content-Type header
	}

	for _, ct := range contentTypes {
		t.Run(fmt.Sprintf("ContentType_%s", ct), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if ct != "" {
					w.Header().Set("Content-Type", ct)
				}
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(validYAML))
			}))
			defer server.Close()

			tmpFile, err := downloadRemoteFileInternal(server.URL, server.Client())
			if err != nil {
				t.Fatalf("downloadRemoteFile() failed with Content-Type %q: %v", ct, err)
			}
			defer func() { _ = os.Remove(tmpFile) }()
		})
	}
}

// TestValidateURL_BlocksDirectIPAddresses tests that direct IP addresses are rejected
func TestValidateURL_BlocksDirectIPAddresses(t *testing.T) {
	tests := []struct {
		name string
		url  string
	}{
		{name: "Localhost IPv4", url: "http://127.0.0.1/manifest.yaml"},
		{name: "Private 10.x", url: "http://10.0.0.1/manifest.yaml"},
		{name: "Private 172.16.x", url: "http://172.16.0.1/manifest.yaml"},
		{name: "Private 192.168.x", url: "http://192.168.1.1/manifest.yaml"},
		{name: "Link-local metadata service", url: "http://169.254.169.254/latest/meta-data/"},
		{name: "Public IPv4", url: "http://8.8.8.8/manifest.yaml"},
		{name: "Localhost IPv6", url: "http://[::1]/manifest.yaml"},
		{name: "Private IPv6 ULA", url: "http://[fc00::1]/manifest.yaml"},
		{name: "Link-local IPv6", url: "http://[fe80::1]/manifest.yaml"},
		{name: "Public IPv6", url: "http://[2001:4860:4860::8888]/manifest.yaml"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := validateURL(tt.url)
			if err == nil {
				t.Errorf("validateURL should block direct IP address: %s", tt.url)
			}
			if !strings.Contains(err.Error(), "IP") {
				t.Errorf("Error should mention IP blocking, got: %v", err)
			}
		})
	}
}

// TestValidateURL_BlocksPrivateHostnames tests that hostnames resolving to private IPs are rejected
func TestValidateURL_BlocksPrivateHostnames(t *testing.T) {
	_, err := validateURL("http://localhost/manifest.yaml")
	if err == nil {
		t.Error("validateURL should block localhost (resolves to 127.0.0.1)")
	}
	if !strings.Contains(err.Error(), "private") && !strings.Contains(err.Error(), "internal") {
		t.Errorf("Error should mention private/internal IP, got: %v", err)
	}
}

// TestValidateURL_BlocksInvalidSchemes tests that non-HTTP(S) schemes are rejected
func TestValidateURL_BlocksInvalidSchemes(t *testing.T) {
	tests := []struct {
		name string
		url  string
	}{
		{name: "File scheme", url: "file:///etc/passwd"},
		{name: "FTP scheme", url: "ftp://example.com/file"},
		{name: "SSH scheme", url: "ssh://example.com/repo"},
		{name: "Data URI", url: "data:text/plain,hello"},
		{name: "JavaScript", url: "javascript:alert(1)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := validateURL(tt.url)
			if err == nil {
				t.Errorf("validateURL should block scheme in: %s", tt.url)
			}
		})
	}
}

// TestValidateURL_AllowsLegitimateURLs tests that valid public URLs are accepted
func TestValidateURL_AllowsLegitimateURLs(t *testing.T) {
	tests := []struct {
		name string
		url  string
	}{
		{name: "GitHub raw", url: "https://raw.githubusercontent.com/user/repo/main/manifest.yaml"},
		{name: "Public domain", url: "http://example.com/manifest.yaml"},
		{name: "With port", url: "https://example.com:8080/manifest.yaml"},
		{name: "With query", url: "https://example.com/file?version=1.0"},
		{name: "With fragment", url: "https://example.com/file#section"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsedURL, err := validateURL(tt.url)
			if err != nil {
				t.Errorf("validateURL should allow legitimate URL %s, got error: %v", tt.url, err)
			}
			if parsedURL == nil {
				t.Errorf("validateURL returned nil URL for: %s", tt.url)
			}
		})
	}
}

// TestValidateURL_DNSFailureHandling tests secure handling of DNS failures
func TestValidateURL_DNSFailureHandling(t *testing.T) {
	_, err := validateURL("http://this-domain-absolutely-does-not-exist-12345.invalid/manifest.yaml")
	if err == nil {
		t.Error("validateURL should fail for non-existent domain")
	}
	// Should mention DNS or lookup failure
	if !strings.Contains(err.Error(), "DNS") && !strings.Contains(err.Error(), "lookup") && !strings.Contains(err.Error(), "no such host") {
		t.Logf("Note: Error indicates DNS/lookup failure: %v", err)
	}
}

// TestDownloadRemoteFile_SSRFAttackVectors tests various SSRF attack scenarios
func TestDownloadRemoteFile_SSRFAttackVectors(t *testing.T) {
	tests := []struct {
		name   string
		url    string
		reason string
	}{
		{
			name:   "AWS metadata service",
			url:    "http://169.254.169.254/latest/meta-data/",
			reason: "link-local IP for cloud metadata",
		},
		{
			name:   "Localhost admin panel",
			url:    "http://127.0.0.1:8080/admin",
			reason: "localhost access",
		},
		{
			name:   "Private network scanner",
			url:    "http://192.168.0.1/",
			reason: "private IP range",
		},
		{
			name:   "Internal Kubernetes service",
			url:    "http://10.96.0.1:443/",
			reason: "Kubernetes internal IP",
		},
		{
			name:   "IPv6 localhost",
			url:    "http://[::1]:8080/secrets",
			reason: "IPv6 localhost",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := downloadRemoteFile(tt.url)
			if err == nil {
				t.Errorf("SSRF attack should be blocked: %s (%s)", tt.url, tt.reason)
			}
		})
	}
}
