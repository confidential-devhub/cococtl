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
	"strings"
	"testing"
	"time"

	"github.com/pelletier/go-toml/v2"

	pkginitdata "github.com/confidential-devhub/cococtl/pkg/initdata"
)

func encodeBlobFromFile(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	_, _ = gz.Write(raw)
	_ = gz.Close()
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

func TestRunValidate_ValidFile(t *testing.T) {
	validateFile = "testdata/valid.toml"
	defer func() { validateFile = "" }()
	if err := runValidate(nil, nil); err != nil {
		t.Errorf("runValidate() unexpected error: %v", err)
	}
}

func TestRunValidate_ValidNoPolicyRego(t *testing.T) {
	validateFile = "testdata/valid-no-policy.toml"
	defer func() { validateFile = "" }()
	if err := runValidate(nil, nil); err != nil {
		t.Errorf("runValidate() should accept missing policy.rego: %v", err)
	}
}

func TestRunValidate_FromStdin(t *testing.T) {
	encoded := encodeBlobFromFile(t, "testdata/valid.toml")
	validateFile = ""
	defer func() { validateFile = "" }()

	r, w, _ := os.Pipe()
	_, _ = w.WriteString(encoded)
	_ = w.Close()
	oldStdin := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = oldStdin; _ = r.Close() }()

	if err := runValidate(nil, nil); err != nil {
		t.Errorf("runValidate() from stdin error: %v", err)
	}
}

func TestRunValidate_WrongVersion(t *testing.T) {
	validateFile = "testdata/invalid-version.toml"
	defer func() { validateFile = "" }()

	err := runValidate(nil, nil)
	if err == nil || !strings.Contains(err.Error(), "version") {
		t.Errorf("expected version error, got: %v", err)
	}
}

func TestRunValidate_WrongAlgorithm(t *testing.T) {
	validateFile = "testdata/invalid-algorithm.toml"
	defer func() { validateFile = "" }()

	err := runValidate(nil, nil)
	if err == nil || !strings.Contains(err.Error(), "algorithm") {
		t.Errorf("expected algorithm error, got: %v", err)
	}
}

func TestRunValidate_MissingRequiredKey(t *testing.T) {
	validateFile = "testdata/invalid-missing-cdh.toml"
	defer func() { validateFile = "" }()

	err := runValidate(nil, nil)
	if err == nil || !strings.Contains(err.Error(), "cdh.toml") {
		t.Errorf("expected missing cdh.toml error, got: %v", err)
	}
}

func TestRunValidate_InvalidEmbeddedCert(t *testing.T) {
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)
	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Bad Leaf"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: false, BasicConstraintsValid: true,
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})

	id := pkginitdata.InitData{
		Version:   pkginitdata.InitDataVersion,
		Algorithm: pkginitdata.InitDataAlgorithm,
		Data: map[string]string{
			"aa.toml": "[token_configs]\n[token_configs.kbs]\nurl = \"http://kbs.test:8080\"\ncert = \"\"\"\n" +
				string(leafPEM) + "\n\"\"\"\n",
			"cdh.toml": "[kbc]\nname = \"cc_kbc\"\nurl = \"http://kbs.test:8080\"\n",
		},
	}
	raw, err := toml.Marshal(id)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	path := t.TempDir() + "/initdata.toml"
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	validateFile = path
	defer func() { validateFile = "" }()

	err = runValidate(nil, nil)
	if err == nil || !strings.Contains(err.Error(), "cert validation failed") {
		t.Errorf("expected cert validation error, got: %v", err)
	}
}
