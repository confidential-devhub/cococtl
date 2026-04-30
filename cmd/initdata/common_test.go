package initdata

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pkginitdata "github.com/confidential-devhub/cococtl/pkg/initdata"
)

func makeTestCACert(t *testing.T) (*x509.Certificate, *rsa.PrivateKey, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, _ := x509.ParseCertificate(der)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return cert, key, pemBytes
}

func makeTestLeafCert(t *testing.T, caCert *x509.Certificate, caKey *rsa.PrivateKey) (*x509.Certificate, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Test Leaf"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  false,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, _ := x509.ParseCertificate(der)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return cert, pemBytes
}

func writeTempPEM(t *testing.T, dir, name string, pemData []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, pemData, 0600); err != nil {
		t.Fatalf("write temp PEM: %v", err)
	}
	return path
}

func TestLoadCerts_SingleCACert(t *testing.T) {
	_, _, pemBytes := makeTestCACert(t)
	path := writeTempPEM(t, t.TempDir(), "ca.pem", pemBytes)
	certs, err := loadCerts(path)
	if err != nil {
		t.Fatalf("loadCerts() error: %v", err)
	}
	if len(certs) != 1 {
		t.Errorf("got %d certs, want 1", len(certs))
	}
}

func TestLoadCerts_MultipleCerts(t *testing.T) {
	_, key, pem1 := makeTestCACert(t)
	block, _ := pem.Decode(pem1)
	ca, _ := x509.ParseCertificate(block.Bytes)
	_, pem2 := makeTestLeafCert(t, ca, key)
	combined := append(pem1, pem2...)
	path := writeTempPEM(t, t.TempDir(), "bundle.pem", combined)
	certs, err := loadCerts(path)
	if err != nil {
		t.Fatalf("loadCerts() error: %v", err)
	}
	if len(certs) != 2 {
		t.Errorf("got %d certs, want 2", len(certs))
	}
}

func TestLoadCerts_NonExistentFile(t *testing.T) {
	_, err := loadCerts("/nonexistent/file.pem")
	if err == nil {
		t.Fatal("expected error for non-existent file")
	}
}

func TestLoadCerts_NoPEMBlocks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "notapem.txt")
	_ = os.WriteFile(path, []byte("hello world"), 0600)
	certs, err := loadCerts(path)
	if err != nil {
		t.Fatalf("loadCerts() error: %v", err)
	}
	if len(certs) != 0 {
		t.Errorf("got %d certs, want 0", len(certs))
	}
}

func TestLoadCertsFromDir_LoadsPEMFiles(t *testing.T) {
	_, _, pem1 := makeTestCACert(t)
	_, _, pem2 := makeTestCACert(t)
	dir := t.TempDir()
	writeTempPEM(t, dir, "a.pem", pem1)
	writeTempPEM(t, dir, "b.pem", pem2)
	certs, err := loadCertsFromDir(dir)
	if err != nil {
		t.Fatalf("loadCertsFromDir() error: %v", err)
	}
	if len(certs) != 2 {
		t.Errorf("got %d certs, want 2", len(certs))
	}
}

func TestLoadCertsFromDir_SkipsNonPEM(t *testing.T) {
	_, _, pemBytes := makeTestCACert(t)
	dir := t.TempDir()
	writeTempPEM(t, dir, "ca.pem", pemBytes)
	_ = os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("not a cert"), 0600)
	certs, err := loadCertsFromDir(dir)
	if err != nil {
		t.Fatalf("loadCertsFromDir() error: %v", err)
	}
	if len(certs) != 1 {
		t.Errorf("got %d certs, want 1", len(certs))
	}
}

func TestValidateCACert_ValidCA(t *testing.T) {
	cert, _, _ := makeTestCACert(t)
	if err := validateCACert(cert); err != nil {
		t.Errorf("validateCACert() unexpected error: %v", err)
	}
}

func TestValidateCACert_LeafCert(t *testing.T) {
	caCert, caKey, _ := makeTestCACert(t)
	leaf, _ := makeTestLeafCert(t, caCert, caKey)
	if err := validateCACert(leaf); err == nil {
		t.Error("validateCACert() should reject leaf cert")
	}
}

func TestValidateCerts_AllValid(t *testing.T) {
	cert1, _, _ := makeTestCACert(t)
	cert2, _, _ := makeTestCACert(t)
	if err := validateCerts([]*x509.Certificate{cert1, cert2}); err != nil {
		t.Errorf("validateCerts() unexpected error: %v", err)
	}
}

func TestValidateCerts_OneInvalid(t *testing.T) {
	caCert, caKey, _ := makeTestCACert(t)
	leaf, _ := makeTestLeafCert(t, caCert, caKey)
	err := validateCerts([]*x509.Certificate{caCert, leaf})
	if err == nil {
		t.Fatal("validateCerts() should fail with one leaf cert")
	}
	if !strings.Contains(err.Error(), "Test Leaf") {
		t.Errorf("error should name the failing cert, got: %v", err)
	}
}

func TestCertsToPEM_RoundTrip(t *testing.T) {
	cert, _, _ := makeTestCACert(t)
	pemStr := certsToPEM([]*x509.Certificate{cert})
	certs, err := loadCerts(writeTempPEM(t, t.TempDir(), "out.pem", []byte(pemStr)))
	if err != nil {
		t.Fatalf("round-trip parse error: %v", err)
	}
	if len(certs) != 1 {
		t.Errorf("got %d certs after round-trip, want 1", len(certs))
	}
	if !certs[0].Equal(cert) {
		t.Error("cert not equal after round-trip")
	}
}

func TestLoadInitdataTOML_FromFile(t *testing.T) {
	content := []byte(`version = "0.1.0"`)
	dir := t.TempDir()
	path := filepath.Join(dir, "initdata.toml")
	_ = os.WriteFile(path, content, 0600)
	got, err := loadInitdataTOML(path, nil)
	if err != nil {
		t.Fatalf("loadInitdataTOML() error: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Errorf("got %q, want %q", got, content)
	}
}

func TestLoadInitdataTOML_FromReader(t *testing.T) {
	raw := []byte("version = \"0.1.0\"\nalgorithm = \"sha256\"\n")
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	_, _ = gz.Write(raw)
	_ = gz.Close()
	encoded := base64.StdEncoding.EncodeToString(buf.Bytes())
	reader := strings.NewReader(encoded)
	got, err := loadInitdataTOML("", reader)
	if err != nil {
		t.Fatalf("loadInitdataTOML() error: %v", err)
	}
	if !bytes.Equal(got, raw) {
		t.Errorf("got %q, want %q", got, raw)
	}
}

func TestExtractCertsFromInitdata_ExtractsCerts(t *testing.T) {
	_, _, pemBytes := makeTestCACert(t)
	aaToml := "[token_configs]\n[token_configs.kbs]\nurl = \"http://kbs.test:8080\"\ncert = \"\"\"\n" +
		string(pemBytes) + "\n\"\"\"\n"
	data := map[string]string{
		"aa.toml":     aaToml,
		"cdh.toml":    "[kbc]\nname = \"cc_kbc\"\nurl = \"http://kbs.test:8080\"\n",
		"policy.rego": "package agent_policy\n",
	}
	certs, err := extractCertsFromInitdata(data)
	if err != nil {
		t.Fatalf("extractCertsFromInitdata() error: %v", err)
	}
	if len(certs) != 1 {
		t.Errorf("got %d certs, want 1", len(certs))
	}
}

func TestExtractCertsFromInitdata_EmptyData(t *testing.T) {
	data := map[string]string{
		"aa.toml":     "[token_configs]\n[token_configs.kbs]\nurl = \"http://kbs.test:8080\"\n",
		"cdh.toml":    "[kbc]\nname = \"cc_kbc\"\nurl = \"http://kbs.test:8080\"\n",
		"policy.rego": "package agent_policy\n",
	}
	certs, err := extractCertsFromInitdata(data)
	if err != nil {
		t.Fatalf("extractCertsFromInitdata() error: %v", err)
	}
	if len(certs) != 0 {
		t.Errorf("got %d certs, want 0", len(certs))
	}
}

func TestLoadConfig_ValidPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cfg.toml")
	_ = os.WriteFile(path, []byte("trustee_server = \"http://kbs.test.svc:8080\"\nruntime_class = \"kata-cc\"\n"), 0600)
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig() error: %v", err)
	}
	if cfg.TrusteeServer == "" {
		t.Error("expected TrusteeServer to be set")
	}
}

func TestLoadConfig_InvalidPath(t *testing.T) {
	_, err := loadConfig("/nonexistent/config.toml")
	if err == nil {
		t.Fatal("expected error for non-existent config file")
	}
}

func TestLoadCertsFromDir_NonRecursive(t *testing.T) {
	_, _, pemBytes := makeTestCACert(t)
	dir := t.TempDir()
	subDir := filepath.Join(dir, "sub")
	_ = os.Mkdir(subDir, 0750)
	// cert inside subdir should NOT be loaded
	_ = os.WriteFile(filepath.Join(subDir, "ca.pem"), pemBytes, 0600)
	certs, err := loadCertsFromDir(dir)
	if err != nil {
		t.Fatalf("loadCertsFromDir() error: %v", err)
	}
	if len(certs) != 0 {
		t.Errorf("got %d certs, want 0 (subdirectory should be skipped)", len(certs))
	}
}

func TestExtractCertsFromInitdata_MalformedTOML(t *testing.T) {
	data := map[string]string{
		"aa.toml":     "this is not [valid toml",
		"cdh.toml":    "[kbc]\nname = \"cc_kbc\"\nurl = \"http://kbs.test:8080\"\n",
		"policy.rego": "package agent_policy\n",
	}
	_, err := extractCertsFromInitdata(data)
	if err == nil {
		t.Fatal("expected error for malformed aa.toml")
	}
}

// Verify pkginitdata import is used (compile check)
var _ = pkginitdata.InitDataVersion
