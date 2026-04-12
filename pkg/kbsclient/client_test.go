package kbsclient

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// generateTestKey returns a fresh Ed25519 key pair for tests.
func generateTestKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() error = %v", err)
	}
	return pub, priv
}

// --- JWT tests ---

func TestSignAdminToken_Structure(t *testing.T) {
	_, priv := generateTestKey(t)

	token, err := signAdminToken(priv)
	if err != nil {
		t.Fatalf("signAdminToken() error = %v", err)
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT parts, got %d", len(parts))
	}
}

func TestSignAdminToken_Header(t *testing.T) {
	_, priv := generateTestKey(t)

	token, err := signAdminToken(priv)
	if err != nil {
		t.Fatalf("signAdminToken() error = %v", err)
	}

	parts := strings.Split(token, ".")
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}

	var header jwtHeader
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		t.Fatalf("unmarshal header: %v", err)
	}

	if header.Alg != "EdDSA" {
		t.Errorf("header.Alg = %q, want %q", header.Alg, "EdDSA")
	}
	if header.Typ != "JWT" {
		t.Errorf("header.Typ = %q, want %q", header.Typ, "JWT")
	}
}

func TestSignAdminToken_Claims(t *testing.T) {
	_, priv := generateTestKey(t)

	token, err := signAdminToken(priv)
	if err != nil {
		t.Fatalf("signAdminToken() error = %v", err)
	}

	parts := strings.Split(token, ".")
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode claims: %v", err)
	}

	var claims jwtClaims
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}

	if claims.Iat <= 0 {
		t.Errorf("claims.Iat = %d, want > 0", claims.Iat)
	}
	if claims.Exp != claims.Iat+adminTokenExpirySecs {
		t.Errorf("claims.Exp-claims.Iat = %d, want %d", claims.Exp-claims.Iat, adminTokenExpirySecs)
	}
}

func TestSignAdminToken_Signature(t *testing.T) {
	pub, priv := generateTestKey(t)

	token, err := signAdminToken(priv)
	if err != nil {
		t.Fatalf("signAdminToken() error = %v", err)
	}

	parts := strings.Split(token, ".")
	signingInput := parts[0] + "." + parts[1]

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}

	if !ed25519.Verify(pub, []byte(signingInput), sig) {
		t.Error("signature verification failed")
	}
}

func TestSignAdminToken_DifferentKeysProduceDifferentSigs(t *testing.T) {
	_, priv1 := generateTestKey(t)
	_, priv2 := generateTestKey(t)

	token1, err := signAdminToken(priv1)
	if err != nil {
		t.Fatalf("signAdminToken() error = %v", err)
	}
	token2, err := signAdminToken(priv2)
	if err != nil {
		t.Fatalf("signAdminToken() error = %v", err)
	}

	parts1 := strings.Split(token1, ".")
	parts2 := strings.Split(token2, ".")
	if parts1[2] == parts2[2] {
		t.Error("expected different signatures for different keys")
	}
}

// --- Client constructor tests ---

func TestNew_InvalidKeySize(t *testing.T) {
	cases := []struct {
		name string
		key  ed25519.PrivateKey
	}{
		{"nil key", nil},
		{"empty key", ed25519.PrivateKey{}},
		{"short key", make(ed25519.PrivateKey, 16)},
		{"long key", make(ed25519.PrivateKey, ed25519.PrivateKeySize+1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New("http://localhost:8080", tc.key, nil)
			if err == nil {
				t.Fatalf("New() with %s: expected error, got nil", tc.name)
			}
		})
	}
}

func TestNew_ValidKey(t *testing.T) {
	_, priv := generateTestKey(t)

	c, err := New("http://localhost:8080", priv, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if c == nil {
		t.Fatal("New() returned nil client")
	}
}

func TestNew_TrailingSlashStripped(t *testing.T) {
	_, priv := generateTestKey(t)

	c, err := New("http://localhost:8080/", priv, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if c.baseURL != "http://localhost:8080" {
		t.Errorf("baseURL = %q, want trailing slash stripped", c.baseURL)
	}
}

func TestNew_InvalidCACert(t *testing.T) {
	_, priv := generateTestKey(t)

	_, err := New("http://localhost:8080", priv, []byte("not a valid pem"))
	if err == nil {
		t.Fatal("New() with invalid CA cert: expected error, got nil")
	}
}

func TestNewFromPEM_ValidKey(t *testing.T) {
	pub, priv := generateTestKey(t)

	// Encode private key as PKCS8 PEM
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey() error = %v", err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})

	c, err := NewFromPEM("http://localhost:8080", privPEM, nil)
	if err != nil {
		t.Fatalf("NewFromPEM() error = %v", err)
	}

	// Verify the parsed key matches by signing a token and verifying with the public key
	token, err := signAdminToken(c.privateKey)
	if err != nil {
		t.Fatalf("signAdminToken() error = %v", err)
	}
	parts := strings.Split(token, ".")
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode JWT signature: %v", err)
	}
	if !ed25519.Verify(pub, []byte(parts[0]+"."+parts[1]), sig) {
		t.Error("signature verification failed after NewFromPEM")
	}
}

func TestNewFromPEM_InvalidPEM(t *testing.T) {
	_, err := NewFromPEM("http://localhost:8080", []byte("not pem"), nil)
	if err == nil {
		t.Fatal("NewFromPEM() with invalid PEM: expected error, got nil")
	}
}

func TestNewFromPEM_WrongKeyType(t *testing.T) {
	// Use an ECDSA private key to trigger the wrong-type error
	privPEM := []byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hD2
cV4Jvmf0rRSQMhzaQNEJMnVdm6GhRANCAATdlatFzEMDiaBiAWBLBnWpVEkWzKGh
WEsKq4n06pFW2PRFV5CFMG6bJsrQvLcmFECrXS/aLQLBJBBklLHnJXaB
-----END PRIVATE KEY-----
`)
	_, err := NewFromPEM("http://localhost:8080", privPEM, nil)
	if err == nil {
		t.Fatal("NewFromPEM() with ECDSA key: expected error, got nil")
	}
}

// --- SetResource tests ---

func TestSetResource_RequestFormat(t *testing.T) {
	pub, priv := generateTestKey(t)
	resourceData := []byte("secret-value")
	resourcePath := "default/my-secret/password"

	var capturedReq *http.Request
	var capturedBody []byte

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedReq = r
		capturedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c, err := New(srv.URL, priv, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if err := c.SetResource(context.Background(), resourcePath, resourceData); err != nil {
		t.Fatalf("SetResource() error = %v", err)
	}

	// Verify HTTP method
	if capturedReq.Method != http.MethodPost {
		t.Errorf("Method = %q, want %q", capturedReq.Method, http.MethodPost)
	}

	// Verify URL path
	wantPath := "/kbs/v0/resource/" + resourcePath
	if capturedReq.URL.Path != wantPath {
		t.Errorf("URL.Path = %q, want %q", capturedReq.URL.Path, wantPath)
	}

	// Verify Content-Type
	if ct := capturedReq.Header.Get("Content-Type"); ct != "application/octet-stream" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/octet-stream")
	}

	// Verify Authorization header is a Bearer token
	auth := capturedReq.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		t.Errorf("Authorization = %q, want Bearer prefix", auth)
	}

	// Verify the token signature
	token := strings.TrimPrefix(auth, "Bearer ")
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("JWT has %d parts, want 3", len(parts))
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode JWT signature: %v", err)
	}
	if !ed25519.Verify(pub, []byte(parts[0]+"."+parts[1]), sig) {
		t.Error("JWT signature verification failed")
	}

	// Verify body
	if string(capturedBody) != string(resourceData) {
		t.Errorf("body = %q, want %q", capturedBody, resourceData)
	}
}

func TestSetResource_ErrorOnNon200(t *testing.T) {
	_, priv := generateTestKey(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("access denied"))
	}))
	defer srv.Close()

	c, err := New(srv.URL, priv, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	err = c.SetResource(context.Background(), "default/secret/key", []byte("data"))
	if err == nil {
		t.Fatal("SetResource() expected error for 401 response, got nil")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("error %q does not mention status 401", err.Error())
	}
	if !strings.Contains(err.Error(), "access denied") {
		t.Errorf("error %q does not include response body", err.Error())
	}
}

func TestSetResource_NetworkError(t *testing.T) {
	_, priv := generateTestKey(t)

	// Use a server that hijacks and immediately closes each connection.
	// This is deterministic: no reliance on a port being unbound between
	// two syscalls, and no dependency on OS-level port reservation.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Error("responsewriter does not implement http.Hijacker")
			return
		}
		conn, _, _ := hj.Hijack()
		_ = conn.Close()
	}))
	defer srv.Close()

	c, err := New(srv.URL, priv, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	err = c.SetResource(context.Background(), "default/secret/key", []byte("data"))
	if err == nil {
		t.Fatal("SetResource() expected network error, got nil")
	}
}

func TestSetResource_CancelledContext(t *testing.T) {
	_, priv := generateTestKey(t)

	// Server that blocks until the context is cancelled
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()

	c, err := New(srv.URL, priv, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	err = c.SetResource(ctx, "default/secret/key", []byte("data"))
	if err == nil {
		t.Fatal("SetResource() expected context cancellation error, got nil")
	}
}

// --- SetResourcePolicy tests ---

func TestSetResourcePolicy_RequestFormat(t *testing.T) {
	pub, priv := generateTestKey(t)
	policy := []byte(`package policy
import rego.v1
default allow = true`)

	var capturedReq *http.Request
	var capturedBody []byte

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedReq = r
		capturedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c, err := New(srv.URL, priv, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if err := c.SetResourcePolicy(context.Background(), policy); err != nil {
		t.Fatalf("SetResourcePolicy() error = %v", err)
	}

	// Verify HTTP method and path
	if capturedReq.Method != http.MethodPost {
		t.Errorf("Method = %q, want %q", capturedReq.Method, http.MethodPost)
	}
	if capturedReq.URL.Path != "/kbs/v0/resource-policy" {
		t.Errorf("URL.Path = %q, want %q", capturedReq.URL.Path, "/kbs/v0/resource-policy")
	}

	// Verify Content-Type
	if ct := capturedReq.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/json")
	}

	// Verify Authorization is a valid Bearer token signed by the key
	auth := capturedReq.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		t.Errorf("Authorization = %q, want Bearer prefix", auth)
	}
	token := strings.TrimPrefix(auth, "Bearer ")
	parts := strings.Split(token, ".")
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode JWT signature: %v", err)
	}
	if !ed25519.Verify(pub, []byte(parts[0]+"."+parts[1]), sig) {
		t.Error("JWT signature verification failed")
	}

	// Verify the body is valid JSON with a base64-encoded "policy" field
	var reqBody resourcePolicyRequest
	if err := json.Unmarshal(capturedBody, &reqBody); err != nil {
		t.Fatalf("unmarshal request body: %v", err)
	}

	decoded, err := base64.StdEncoding.DecodeString(reqBody.Policy)
	if err != nil {
		t.Fatalf("decode policy field: %v", err)
	}
	if string(decoded) != string(policy) {
		t.Errorf("decoded policy = %q, want %q", decoded, policy)
	}
}

func TestSetResourcePolicy_ErrorOnNon200(t *testing.T) {
	_, priv := generateTestKey(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("forbidden"))
	}))
	defer srv.Close()

	c, err := New(srv.URL, priv, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	err = c.SetResourcePolicy(context.Background(), []byte("policy"))
	if err == nil {
		t.Fatal("SetResourcePolicy() expected error for 403 response, got nil")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Errorf("error %q does not mention status 403", err.Error())
	}
}

// --- validateResourcePath tests ---

func TestValidateResourcePath_Valid(t *testing.T) {
	cases := []string{
		"default/my-secret/password",
		"default/attestation-status/status",
		"ns/sidecar-tls-app/server-cert",
		"a/b/c",
	}
	for _, path := range cases {
		if err := validateResourcePath(path); err != nil {
			t.Errorf("validateResourcePath(%q) error = %v, want nil", path, err)
		}
	}
}

func TestValidateResourcePath_Traversal(t *testing.T) {
	cases := []string{
		"../../etc/passwd",
		"default/../secret/key",
		"default/secret/../../key",
	}
	for _, path := range cases {
		if err := validateResourcePath(path); err == nil {
			t.Errorf("validateResourcePath(%q) = nil, want error for traversal", path)
		}
	}
}

func TestValidateResourcePath_WrongSegments(t *testing.T) {
	cases := []string{
		"only-one-part",
		"only/two",
		"too/many/parts/here",
		"",
	}
	for _, path := range cases {
		if err := validateResourcePath(path); err == nil {
			t.Errorf("validateResourcePath(%q) = nil, want error for wrong segment count", path)
		}
	}
}

func TestValidateResourcePath_InvalidChars(t *testing.T) {
	cases := []string{
		"default/secret/key?x=y",  // query string injection
		"default/secret/key#frag", // fragment injection
		"default/secret/key%20",   // URL encoding
		"default/my secret/key",   // space
		".hidden/secret/key",      // leading dot in segment
	}
	for _, path := range cases {
		if err := validateResourcePath(path); err == nil {
			t.Errorf("validateResourcePath(%q) = nil, want error for invalid chars", path)
		}
	}
}

func TestValidateResourcePath_EmptySegment(t *testing.T) {
	cases := []string{
		"/secret/key",
		"default//key",
		"default/secret/",
	}
	for _, path := range cases {
		if err := validateResourcePath(path); err == nil {
			t.Errorf("validateResourcePath(%q) = nil, want error for empty segment", path)
		}
	}
}

func TestSetResource_InvalidPath(t *testing.T) {
	_, priv := generateTestKey(t)

	c, err := New("http://localhost:8080", priv, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	err = c.SetResource(context.Background(), "../../etc/passwd", []byte("data"))
	if err == nil {
		t.Fatal("SetResource() with traversal path: expected error, got nil")
	}
}

func TestSetResource_EmptyData(t *testing.T) {
	_, priv := generateTestKey(t)

	var capturedBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c, err := New(srv.URL, priv, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if err := c.SetResource(context.Background(), "default/secret/key", []byte{}); err != nil {
		t.Fatalf("SetResource() with empty data error = %v", err)
	}
	if len(capturedBody) != 0 {
		t.Errorf("expected empty body, got %d bytes", len(capturedBody))
	}
}

func TestSetResource_ErrorBodyCapped(t *testing.T) {
	_, priv := generateTestKey(t)

	// Server returns a body larger than errorBodyLimit
	largeBody := strings.Repeat("x", errorBodyLimit*2)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(largeBody))
	}))
	defer srv.Close()

	c, err := New(srv.URL, priv, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	err = c.SetResource(context.Background(), "default/secret/key", []byte("data"))
	if err == nil {
		t.Fatal("SetResource() expected error for 500, got nil")
	}
	// Error message must not contain the full large body
	if len(err.Error()) > errorBodyLimit+200 {
		t.Errorf("error message length %d exceeds cap; response body not limited", len(err.Error()))
	}
}

func TestNew_KeyCopied(t *testing.T) {
	_, priv := generateTestKey(t)

	// Make a copy to compare against after zeroing the original
	privCopy := append(ed25519.PrivateKey{}, priv...)

	c, err := New("http://localhost:8080", priv, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Zero the original slice
	for i := range priv {
		priv[i] = 0
	}

	// The client's internal key must still match the original value
	if string(c.privateKey) != string(privCopy) {
		t.Error("New() did not copy the private key; zeroing caller's slice corrupted the client key")
	}
}

func TestNew_TLSWithCustomCA(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Extract the test server's self-signed certificate as PEM
	tlsCert := srv.Certificate()
	caCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: tlsCert.Raw,
	})

	_, priv := generateTestKey(t)
	c, err := New(srv.URL, priv, caCertPEM)
	if err != nil {
		t.Fatalf("New() with TLS CA error = %v", err)
	}

	// A successful request proves the custom CA was used for TLS verification
	if err := c.SetResource(context.Background(), "default/secret/key", []byte("data")); err != nil {
		t.Fatalf("SetResource() with custom CA error = %v", err)
	}
}
