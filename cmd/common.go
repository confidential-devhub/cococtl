package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	// maxYAMLDocuments is the maximum number of YAML documents allowed in a manifest file
	// Typical K8s manifests have 1-5 documents. This limit protects against accidentally
	// parsing non-YAML content (like HTML) which could be interpreted as many documents.
	maxYAMLDocuments = 10

	// maxManifestSize is the maximum size allowed for a remote manifest file
	// Typical K8s manifests are a few KB. This limit (10MB) protects against excessive
	// disk usage from malicious or misconfigured remote URLs.
	maxManifestSize = 10 * 1024 * 1024 // 10MB

	// maxRedirects is the maximum number of HTTP redirects to follow
	// This prevents redirect loops and excessive redirect chains.
	maxRedirects = 5
)

// isRemoteFile checks if the given path is a URL
func isRemoteFile(path string) bool {
	u, err := url.Parse(path)
	if err != nil {
		return false
	}
	return u.Scheme == "http" || u.Scheme == "https"
}

// isPrivateIP checks if an IP address is in a private/internal range
func isPrivateIP(ip net.IP) bool {
	// Check for loopback addresses (127.0.0.0/8, ::1)
	if ip.IsLoopback() {
		return true
	}

	// Check for link-local addresses (169.254.0.0/16, fe80::/10)
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}

	// Check for private IPv4 ranges
	// 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
	privateIPv4Ranges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
	}

	for _, cidr := range privateIPv4Ranges {
		_, network, _ := net.ParseCIDR(cidr)
		if network.Contains(ip) {
			return true
		}
	}

	// Check for private IPv6 ranges (fc00::/7 - Unique Local Addresses)
	if len(ip) == net.IPv6len && (ip[0] == 0xfc || ip[0] == 0xfd) {
		return true
	}

	return false
}

// validateURL validates a URL and checks that it doesn't use direct IP addresses
func validateURL(urlStr string) (*url.URL, error) {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	// Only allow http and https schemes
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return nil, fmt.Errorf("unsupported URL scheme: %s (only http and https are allowed)", parsedURL.Scheme)
	}

	hostname := parsedURL.Hostname()
	if hostname == "" {
		return nil, errors.New("URL must contain a hostname")
	}

	// Block direct IP addresses (both IPv4 and IPv6)
	if net.ParseIP(hostname) != nil {
		return nil, errors.New("direct IP addresses are not allowed, use hostnames instead")
	}

	// Perform DNS lookup to validate hostname resolves to public IPs
	ips, err := net.LookupIP(hostname)
	if err != nil {
		return nil, fmt.Errorf("DNS lookup failed for %s: %w", hostname, err)
	}

	// Validate that ALL resolved IPs are public (not private/internal)
	for _, ip := range ips {
		if isPrivateIP(ip) {
			return nil, fmt.Errorf("URL blocked: %s resolves to private/internal IP address %s", hostname, ip.String())
		}
	}

	return parsedURL, nil
}

// downloadRemoteFile downloads a remote file and returns the path to a temporary file
func downloadRemoteFile(remoteURL string) (string, error) {
	return downloadRemoteFileInternal(remoteURL, nil)
}

// downloadRemoteFileInternal downloads a remote file with an optional custom HTTP client
// If client is nil, validates URL and creates a secure client with SSRF protection
// This internal function is used for testing
func downloadRemoteFileInternal(remoteURL string, client *http.Client) (string, error) {
	// If no client provided, validate URL and create secure client (production path)
	if client == nil {
		// Validate the initial URL before making any requests (SSRF protection)
		_, err := validateURL(remoteURL)
		if err != nil {
			return "", fmt.Errorf("URL validation failed: %w", err)
		}

		// Track redirect count to prevent loops and excessive redirects
		redirectCount := 0

		// Create HTTP client with custom transport to prevent DNS rebinding attacks
		client = &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				// Custom DialContext that validates IPs at connection time
				// This prevents TOCTOU/DNS rebinding attacks where DNS changes between lookup and connection
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					// Parse host:port
					host, _, err := net.SplitHostPort(addr)
					if err != nil {
						return nil, fmt.Errorf("invalid address: %w", err)
					}

					// Block direct IP addresses
					if net.ParseIP(host) != nil {
						return nil, errors.New("direct IP addresses are not allowed")
					}

					// Resolve hostname at connection time (not earlier) to prevent DNS rebinding
					ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
					if err != nil {
						return nil, fmt.Errorf("DNS lookup failed: %w", err)
					}

					// Validate ALL resolved IPs are public (SSRF protection)
					for _, ip := range ips {
						if isPrivateIP(ip) {
							return nil, fmt.Errorf("connection blocked: %s resolves to private/internal IP %s", host, ip.String())
						}
					}

					// Use standard dialer to establish connection
					dialer := &net.Dialer{
						Timeout:   10 * time.Second,
						KeepAlive: 30 * time.Second,
					}
					return dialer.DialContext(ctx, network, addr)
				},
			},
			CheckRedirect: func(req *http.Request, _ []*http.Request) error {
				// Limit number of redirects
				redirectCount++
				if redirectCount > maxRedirects {
					return fmt.Errorf("too many redirects (max: %d)", maxRedirects)
				}

				// Validate redirect URL scheme
				if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
					return fmt.Errorf("redirect to unsupported scheme: %s", req.URL.Scheme)
				}

				// Validate redirect URL
				hostname := req.URL.Hostname()

				// Block direct IP addresses in redirects
				if net.ParseIP(hostname) != nil {
					return errors.New("redirect to direct IP address blocked")
				}

				// Resolve hostname to IP addresses for SSRF protection
				// Note: We use net.LookupIP without context here because http.Client's CheckRedirect callback
				// does not provide a context parameter.
				ips, err := net.LookupIP(hostname)
				if err != nil {
					// Fail securely: DNS lookup failures should block the redirect
					return fmt.Errorf("redirect blocked: DNS lookup failed for %s: %w", hostname, err)
				}

				// Check if any resolved IP is private/internal (SSRF protection)
				for _, ip := range ips {
					if isPrivateIP(ip) {
						return fmt.Errorf("redirect to private/internal IP address blocked: %s resolves to %s", hostname, ip.String())
					}
				}

				return nil
			},
		}
	}

	// Download the file
	// #nosec G107 - URL is user-provided manifest location
	resp, err := client.Get(remoteURL)
	if err != nil {
		return "", fmt.Errorf("failed to download remote file: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to download remote file: HTTP %d", resp.StatusCode)
	}

	// Check Content-Length header if available to fail fast
	if resp.ContentLength > 0 && resp.ContentLength > maxManifestSize {
		return "", fmt.Errorf("remote file too large: %d bytes (max: %d bytes)", resp.ContentLength, maxManifestSize)
	}

	// Check Content-Type header (if present)
	// Note: We don't enforce Content-Type validation because some servers
	// (like GitHub raw.githubusercontent.com) serve YAML as text/plain
	contentType := resp.Header.Get("Content-Type")

	// Use LimitReader as safety net to enforce hard limit
	// (in case Content-Length is not set, incorrect, or malicious)
	// Read one extra byte to detect if limit was exceeded
	limitedReader := io.LimitReader(resp.Body, maxManifestSize+1)
	content, err := io.ReadAll(limitedReader)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	// Check if we exceeded the size limit
	if len(content) > maxManifestSize {
		return "", fmt.Errorf("remote file too large: exceeds maximum size of %d bytes", maxManifestSize)
	}

	// Validate that content is valid YAML
	if err := validateYAML(content); err != nil {
		return "", fmt.Errorf("downloaded content is not valid YAML: %w\nURL: %s\nContent-Type: %s", err, remoteURL, contentType)
	}

	// Create temporary file
	tmpFile, err := os.CreateTemp("", "kubectl-coco-*.yaml")
	if err != nil {
		return "", fmt.Errorf("failed to create temporary file: %w", err)
	}

	var success bool
	defer func() {
		_ = tmpFile.Close()
		if !success {
			_ = os.Remove(tmpFile.Name())
		}
	}()

	// Write validated content to temporary file
	_, err = tmpFile.Write(content)
	if err != nil {
		return "", fmt.Errorf("failed to write temporary file: %w", err)
	}

	success = true
	return tmpFile.Name(), nil
}

// validateYAML checks if the content is valid YAML
func validateYAML(content []byte) error {
	// Try to parse as YAML
	decoder := yaml.NewDecoder(bytes.NewReader(content))

	// Attempt to decode all documents in the YAML
	var docCount int
	for {
		var doc interface{}
		err := decoder.Decode(&doc)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("YAML parsing error: %w", err)
		}
		docCount++

		// Sanity check: protect against accidentally parsing non-YAML content
		if docCount > maxYAMLDocuments {
			return fmt.Errorf("file contains too many YAML documents (>%d), might not be a valid manifest", maxYAMLDocuments)
		}
	}

	// Check if we got at least one document
	if docCount == 0 {
		return fmt.Errorf("file is empty or contains no valid YAML documents")
	}

	return nil
}
