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

	"github.com/pelletier/go-toml/v2"

	pkginitdata "github.com/confidential-devhub/cococtl/pkg/initdata"
)

func validInitData() pkginitdata.InitData {
	return pkginitdata.InitData{
		Version:   pkginitdata.InitDataVersion,
		Algorithm: pkginitdata.InitDataAlgorithm,
		Data: map[string]string{
			"aa.toml":     "[token_configs]\n[token_configs.kbs]\nurl = \"http://kbs.test:8080\"\n",
			"cdh.toml":    "[kbc]\nname = \"cc_kbc\"\nurl = \"http://kbs.test:8080\"\n",
			"policy.rego": "package agent_policy\n",
		},
	}
}

func marshalToFile(t *testing.T, dir, name string, id pkginitdata.InitData) string {
	t.Helper()
	raw, err := toml.Marshal(id)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	path := filepath.Join(dir, name)
	_ = os.WriteFile(path, raw, 0600)
	return path
}

func encodeBlob(t *testing.T, id pkginitdata.InitData) string {
	t.Helper()
	raw, err := toml.Marshal(id)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	_, _ = gz.Write(raw)
	_ = gz.Close()
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

func TestRunValidate_ValidFile(t *testing.T) {
	path := marshalToFile(t, t.TempDir(), "initdata.toml", validInitData())
	validateFile = path
	defer func() { validateFile = "" }()
	if err := runValidate(nil, nil); err != nil {
		t.Errorf("runValidate() unexpected error: %v", err)
	}
}

func TestRunValidate_FromStdin(t *testing.T) {
	encoded := encodeBlob(t, validInitData())
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
	id := validInitData()
	id.Version = "9.9.9"
	path := marshalToFile(t, t.TempDir(), "initdata.toml", id)
	validateFile = path
	defer func() { validateFile = "" }()

	err := runValidate(nil, nil)
	if err == nil || !strings.Contains(err.Error(), "version") {
		t.Errorf("expected version error, got: %v", err)
	}
}

func TestRunValidate_WrongAlgorithm(t *testing.T) {
	id := validInitData()
	id.Algorithm = "md5"
	path := marshalToFile(t, t.TempDir(), "initdata.toml", id)
	validateFile = path
	defer func() { validateFile = "" }()

	err := runValidate(nil, nil)
	if err == nil || !strings.Contains(err.Error(), "algorithm") {
		t.Errorf("expected algorithm error, got: %v", err)
	}
}

func TestRunValidate_MissingKey(t *testing.T) {
	id := validInitData()
	delete(id.Data, "policy.rego")
	path := marshalToFile(t, t.TempDir(), "initdata.toml", id)
	validateFile = path
	defer func() { validateFile = "" }()

	err := runValidate(nil, nil)
	if err == nil || !strings.Contains(err.Error(), "policy.rego") {
		t.Errorf("expected missing key error, got: %v", err)
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

	id := validInitData()
	id.Data["aa.toml"] = "[token_configs]\n[token_configs.kbs]\nurl = \"http://kbs.test:8080\"\ncert = \"\"\"\n" +
		string(leafPEM) + "\n\"\"\"\n"
	path := marshalToFile(t, t.TempDir(), "initdata.toml", id)
	validateFile = path
	defer func() { validateFile = "" }()

	err := runValidate(nil, nil)
	if err == nil || !strings.Contains(err.Error(), "cert validation failed") {
		t.Errorf("expected cert validation error, got: %v", err)
	}
}
