package certs

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestSaveToPKCS12(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not in PATH; skipping PKCS#12 export test")
	}

	ca, err := GenerateCA("Test CA")
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	clientCert, err := GenerateClientCert(ca.CertPEM, ca.KeyPEM, "test-client")
	if err != nil {
		t.Fatalf("GenerateClientCert: %v", err)
	}

	tmp := t.TempDir()
	if err := clientCert.SaveToFile(tmp, "client"); err != nil {
		t.Fatalf("SaveToFile: %v", err)
	}

	certPath := filepath.Join(tmp, "client-cert.pem")
	keyPath := filepath.Join(tmp, "client-key.pem")
	p12Path := filepath.Join(tmp, "client.p12")
	friendly := "coco mTLS client"

	if err := SaveToPKCS12(certPath, keyPath, p12Path, friendly, ""); err != nil {
		t.Fatalf("SaveToPKCS12: %v", err)
	}

	// openssl creates the file; ensure it is non-empty
	info, err := os.Stat(p12Path)
	if err != nil {
		t.Fatalf("stat PKCS#12 output: %v", err)
	}
	if info.Size() == 0 {
		t.Fatal("PKCS#12 file is empty")
	}

	// Parse bundle back with openssl (empty export password, same as init)
	// #nosec G204 -- test-only: fixed openssl subcommand and paths from t.TempDir()
	cmd := exec.Command("openssl", "pkcs12", "-in", p12Path,
		"-passin", "pass:", "-nokeys")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("openssl pkcs12 -in (verify): %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "BEGIN CERTIFICATE") {
		t.Fatalf("parsed PKCS#12 should contain a PEM certificate; got:\n%s", out)
	}
}
