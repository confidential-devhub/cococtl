package initdata

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pelletier/go-toml/v2"

	pkginitdata "github.com/confidential-devhub/cococtl/pkg/initdata"
)

func makeCACertPEMFile(t *testing.T, dir, name string) string {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	path := filepath.Join(dir, name)
	_ = os.WriteFile(path, pemBytes, 0600)
	return path
}

func makeLeafCertPEMFile(t *testing.T, dir, name string) string {
	t.Helper()
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)
	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Leaf"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  false,
		BasicConstraintsValid: true,
	}
	der, _ := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	path := filepath.Join(dir, name)
	_ = os.WriteFile(path, pemBytes, 0600)
	return path
}

func makeTestConfigFile(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "coco-config.toml")
	_ = os.WriteFile(path, []byte("trustee_server = \"http://kbs.test.svc:8080\"\nruntime_class = \"kata-cc\"\n"), 0600)
	return path
}

func TestRunCreate_MutuallyExclusive(t *testing.T) {
	createCACert = "/some/cert.pem"
	createCAPath = "/some/dir"
	defer func() { createCACert = ""; createCAPath = "" }()
	err := runCreate(nil, nil)
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("expected mutually exclusive error, got: %v", err)
	}
}

func TestRunCreate_NoCert_WritesFile(t *testing.T) {
	dir := t.TempDir()
	createConfigPath = makeTestConfigFile(t, dir)
	createCACert = ""
	createCAPath = ""
	createOutput = filepath.Join(dir, "initdata.toml")
	defer func() { createConfigPath = ""; createOutput = "" }()

	if err := runCreate(nil, nil); err != nil {
		t.Fatalf("runCreate() error: %v", err)
	}
	data, err := os.ReadFile(createOutput)
	if err != nil {
		t.Fatalf("output file not written: %v", err)
	}
	var id pkginitdata.InitData
	if err := toml.Unmarshal(data, &id); err != nil {
		t.Fatalf("output is not valid TOML: %v", err)
	}
	if id.Version != pkginitdata.InitDataVersion {
		t.Errorf("version = %q, want %q", id.Version, pkginitdata.InitDataVersion)
	}
}

func TestRunCreate_WithCACert_EmbedsCert(t *testing.T) {
	dir := t.TempDir()
	createConfigPath = makeTestConfigFile(t, dir)
	createCACert = makeCACertPEMFile(t, dir, "ca.pem")
	createCAPath = ""
	createOutput = filepath.Join(dir, "initdata.toml")
	defer func() { createConfigPath = ""; createCACert = ""; createOutput = "" }()

	if err := runCreate(nil, nil); err != nil {
		t.Fatalf("runCreate() error: %v", err)
	}
	data, _ := os.ReadFile(createOutput)
	if !strings.Contains(string(data), "CERTIFICATE") {
		t.Error("output TOML should contain embedded certificate")
	}
}

func TestRunCreate_WithCAPath_LoadsDir(t *testing.T) {
	dir := t.TempDir()
	certDir := filepath.Join(dir, "certs")
	_ = os.Mkdir(certDir, 0750)
	makeCACertPEMFile(t, certDir, "ca1.pem")
	makeCACertPEMFile(t, certDir, "ca2.pem")
	createConfigPath = makeTestConfigFile(t, dir)
	createCACert = ""
	createCAPath = certDir
	createOutput = filepath.Join(dir, "initdata.toml")
	defer func() { createConfigPath = ""; createCAPath = ""; createOutput = "" }()

	if err := runCreate(nil, nil); err != nil {
		t.Fatalf("runCreate() error: %v", err)
	}
	data, _ := os.ReadFile(createOutput)
	if !strings.Contains(string(data), "CERTIFICATE") {
		t.Error("output TOML should contain embedded certificates")
	}
}

func TestRunCreate_RejectsLeafCert(t *testing.T) {
	dir := t.TempDir()
	createConfigPath = makeTestConfigFile(t, dir)
	createCACert = makeLeafCertPEMFile(t, dir, "leaf.pem")
	createCAPath = ""
	createOutput = filepath.Join(dir, "initdata.toml")
	defer func() { createConfigPath = ""; createCACert = ""; createOutput = "" }()

	err := runCreate(nil, nil)
	if err == nil {
		t.Fatal("expected error for leaf cert, got nil")
	}
	if !strings.Contains(err.Error(), "cert validation failed") {
		t.Errorf("expected cert validation error, got: %v", err)
	}
}

func TestRunCreate_EmptyCACert_Errors(t *testing.T) {
	dir := t.TempDir()
	// Write a file with no PEM blocks
	emptyPath := filepath.Join(dir, "empty.pem")
	_ = os.WriteFile(emptyPath, []byte("not a cert\n"), 0600)
	createConfigPath = makeTestConfigFile(t, dir)
	createCACert = emptyPath
	createCAPath = ""
	createOutput = filepath.Join(dir, "initdata.toml")
	defer func() { createConfigPath = ""; createCACert = ""; createOutput = "" }()

	err := runCreate(nil, nil)
	if err == nil || !strings.Contains(err.Error(), "no certificates found") {
		t.Errorf("expected no-certs error, got: %v", err)
	}
}

func TestRunCreate_OutputFileMode(t *testing.T) {
	dir := t.TempDir()
	createConfigPath = makeTestConfigFile(t, dir)
	createCACert = ""
	createCAPath = ""
	createOutput = filepath.Join(dir, "initdata.toml")
	defer func() { createConfigPath = ""; createOutput = "" }()

	if err := runCreate(nil, nil); err != nil {
		t.Fatalf("runCreate() error: %v", err)
	}
	info, err := os.Stat(createOutput)
	if err != nil {
		t.Fatalf("stat output file: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("file mode = %o, want 0600", info.Mode().Perm())
	}
}
