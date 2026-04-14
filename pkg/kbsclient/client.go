// Package kbsclient provides a client for the KBS (Key Broker Service) admin HTTP API.
// It implements the same protocol as the kbs-client tool from the confidential-containers/trustee
// repository: JWT Bearer tokens signed with an Ed25519 private key, validated on the KBS side
// against pre-configured public keys.
package kbsclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// resourcePathRegexp enforces the KBS resource path pattern:
// ^[a-zA-Z0-9_-]+[a-zA-Z0-9_-.]*\/[a-zA-Z0-9_-]+[a-zA-Z0-9_-.]*\/[a-zA-Z0-9_-]+[a-zA-Z0-9_-.]*$
// Each segment must start with an alphanumeric, underscore, or hyphen character
// and may be followed by the same characters plus dots.  This excludes characters
// such as '?', '#', '%', and spaces that would corrupt the URL or enable injection.
var resourcePathRegexp = regexp.MustCompile(`^[a-zA-Z0-9_-][a-zA-Z0-9_.-]*\/[a-zA-Z0-9_-][a-zA-Z0-9_.-]*\/[a-zA-Z0-9_-][a-zA-Z0-9_.-]*$`)

const (
	kbsAPIPrefix = "/kbs/v0"

	// requestTimeout is the per-request deadline for KBS admin API calls.
	requestTimeout = 30 * time.Second

	// errorBodyLimit caps the bytes read from an error response body to avoid
	// unbounded memory use if the server (or a MITM) returns a large body.
	errorBodyLimit = 4096
)

// Client is a client for the KBS admin HTTP API.
type Client struct {
	baseURL    string
	privateKey ed25519.PrivateKey
	httpClient *http.Client
}

// New creates a Client using a parsed Ed25519 private key.
// baseURL is the KBS server base URL (e.g. "http://localhost:8080").
// caCert is an optional PEM-encoded CA certificate; pass nil to use system roots.
//
// New copies privateKey internally; the caller may zero it after this call returns.
func New(baseURL string, privateKey ed25519.PrivateKey, caCert []byte) (*Client, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid Ed25519 private key: got %d bytes, want %d", len(privateKey), ed25519.PrivateKeySize)
	}

	// Clone the default transport so we inherit connection pooling, timeouts,
	// proxy settings, etc., and only override what we need.
	// Guard the type assertion in case DefaultTransport has been replaced.
	dt, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		dt = &http.Transport{}
	}
	transport := dt.Clone()

	if len(caCert) > 0 {
		// Start from the system pool so that public certificates are still
		// trusted alongside the custom CA.
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate PEM")
		}
		// #nosec G402 - RootCAs is set explicitly; InsecureSkipVerify is not set
		transport.TLSClientConfig = &tls.Config{RootCAs: pool}
	}

	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		// Copy the key so the caller zeroing their copy does not corrupt ours.
		privateKey: append(ed25519.PrivateKey{}, privateKey...),
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   requestTimeout,
		},
	}, nil
}

// NewFromPEM creates a Client from a PEM-encoded PKCS#8 Ed25519 private key.
// This is the typical constructor when the key is loaded from disk.
// caCert is an optional PEM-encoded CA certificate; pass nil to use system roots.
func NewFromPEM(baseURL string, privateKeyPEM []byte, caCert []byte) (*Client, error) {
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block from private key")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	privKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("expected Ed25519 private key, got %T", key)
	}

	return New(baseURL, privKey, caCert)
}

// SetResource uploads a resource to the KBS repository.
// resourcePath must be in "repository/type/tag" format
// (e.g. "default/my-secret/password"). The data is sent as raw bytes.
func (c *Client) SetResource(ctx context.Context, resourcePath string, data []byte) error {
	if err := validateResourcePath(resourcePath); err != nil {
		return err
	}

	token, err := signAdminToken(c.privateKey)
	if err != nil {
		return fmt.Errorf("sign admin token: %w", err)
	}

	url := c.baseURL + kbsAPIPrefix + "/resource/" + resourcePath
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Authorization", "Bearer "+token)

	return c.doRequest(req)
}

// resourcePolicyRequest is the JSON body for the resource-policy endpoint.
type resourcePolicyRequest struct {
	Policy string `json:"policy"`
}

// SetResourcePolicy uploads an OPA resource policy to KBS.
// policy is the raw Rego policy bytes; it is base64-encoded before sending.
func (c *Client) SetResourcePolicy(ctx context.Context, policy []byte) error {
	token, err := signAdminToken(c.privateKey)
	if err != nil {
		return fmt.Errorf("sign admin token: %w", err)
	}

	body, err := json.Marshal(resourcePolicyRequest{
		Policy: base64.StdEncoding.EncodeToString(policy),
	})
	if err != nil {
		return fmt.Errorf("marshal policy request: %w", err)
	}

	url := c.baseURL + kbsAPIPrefix + "/resource-policy"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	return c.doRequest(req)
}

// doRequest executes an HTTP request and returns an error for non-200 responses.
// The KBS set-resource endpoint returns 200 OK on success (confirmed against
// confidential-containers/trustee api_server.rs: HttpResponse::Ok()).
// The response body is included in errors to aid diagnostics, capped at
// errorBodyLimit bytes to prevent unbounded memory use.
func (c *Client) doRequest(req *http.Request) error {
	resp, err := c.httpClient.Do(req) // #nosec G704 -- baseURL is set at construction time from trusted config, not from user input
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode == http.StatusOK {
		return nil
	}

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, errorBodyLimit))
	return fmt.Errorf("KBS returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
}

// validateResourcePath checks that resourcePath matches the KBS regex:
// ^[a-zA-Z0-9_-]+[a-zA-Z0-9_-.]*\/[a-zA-Z0-9_-]+[a-zA-Z0-9_-.]*\/[a-zA-Z0-9_-]+[a-zA-Z0-9_-.]*$
// This enforces exactly three slash-separated segments, each starting with an
// alphanumeric/underscore/hyphen character, and rejects characters such as '?',
// '#', '%', spaces, and leading dots that would corrupt the URL or enable injection.
func validateResourcePath(resourcePath string) error {
	if !resourcePathRegexp.MatchString(resourcePath) {
		return fmt.Errorf("invalid resource path %q: must be 'repository/type/tag' with each segment matching [a-zA-Z0-9_-][a-zA-Z0-9_-.]*", resourcePath)
	}
	return nil
}
