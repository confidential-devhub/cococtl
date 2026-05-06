//go:build ignore

// Command gen generates long-lived certificate fixtures for cmd/initdata tests.
// Private keys are generated in memory only and never written to disk.
//
// Run from the cmd/initdata directory:
//
//	go run testdata/gen/main.go
//
// Or from the repository root via go generate:
//
//	go generate ./cmd/initdata/
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"
)

const (
	kbsURL  = "http://kbs.example.svc:8080"
	outDir  = "testdata"
	keyBits = 2048
)

const defaultPolicy = `package agent_policy

default CreateContainerRequest := true
default ExecProcessRequest := false
`

func mustGenKey() *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, keyBits)
	if err != nil {
		log.Fatal(err)
	}
	return k
}

func mustCreateCert(tmpl, parent *x509.Certificate, pub interface{}, signer interface{}) ([]byte, *x509.Certificate) {
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		log.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		log.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return pemBytes, cert
}

// innerTOML marshals a config map to a TOML string using go-toml so the
// encoding (including multiline cert fields) is consistent with the runtime.
func innerTOML(config map[string]interface{}) string {
	b, err := toml.Marshal(config)
	if err != nil {
		log.Fatal(err)
	}
	return string(b)
}

// buildFixture assembles the outer initdata TOML using ''' literal strings for
// the data section so that inner """ sequences in cert fields are safe.
func buildFixture(data map[string]string) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "version = %q\n", "0.1.0")
	fmt.Fprintf(&sb, "algorithm = %q\n", "sha256")
	sb.WriteString("\n[data]\n")

	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		v := data[k]
		if !strings.HasSuffix(v, "\n") {
			v += "\n"
		}
		fmt.Fprintf(&sb, "\n%q = '''\n%s'''\n", k, v)
	}
	return sb.String()
}

func writeFixture(name, content string) {
	path := outDir + "/" + name
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		log.Fatalf("write %s: %v", path, err)
	}
	fmt.Printf("  wrote %s\n", name)
}

func aaToml(certPEM string) map[string]interface{} {
	kbs := map[string]interface{}{"url": kbsURL}
	if certPEM != "" {
		kbs["cert"] = certPEM
	}
	return map[string]interface{}{
		"token_configs": map[string]interface{}{"kbs": kbs},
	}
}

func cdhToml(certPEM string) map[string]interface{} {
	kbc := map[string]interface{}{"name": "cc_kbc", "url": kbsURL}
	if certPEM != "" {
		kbc["kbs_cert"] = certPEM
	}
	return map[string]interface{}{"kbc": kbc}
}

func main() {
	// Primary CA cert — 100-year validity so the fixture never expires in practice.
	caKey := mustGenKey()
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(100, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caPEM, caCert := mustCreateCert(caTmpl, caTmpl, &caKey.PublicKey, caKey)

	// Second CA cert — used in valid-with-both.toml so both cert positions carry a CA.
	ca2Key := mustGenKey()
	ca2Tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(5),
		Subject:               pkix.Name{CommonName: "Test CA 2"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(100, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	ca2PEM, _ := mustCreateCert(ca2Tmpl, ca2Tmpl, &ca2Key.PublicKey, ca2Key)

	// Leaf cert — signed by the test CA. Used in invalid-leaf-cert.toml.
	leafKey := mustGenKey()
	leafTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "kbs.example.svc"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(100, 0, 0),
		IsCA:                  false,
		BasicConstraintsValid: true,
		DNSNames:              []string{"kbs.example.svc"},
		IPAddresses:           []net.IP{net.ParseIP("10.0.0.1")},
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature,
	}
	leafPEM, _ := mustCreateCert(leafTmpl, caCert, &leafKey.PublicKey, caKey)

	// Expired CA cert — hardcoded past dates so it is always expired.
	expKey := mustGenKey()
	expTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(3),
		Subject:               pkix.Name{CommonName: "Expired CA"},
		NotBefore:             time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	expPEM, _ := mustCreateCert(expTmpl, expTmpl, &expKey.PublicKey, expKey)

	// Non-CA leaf cert with no SAN — fails on two counts: not a CA cert, no SAN.
	badLeafKey := mustGenKey()
	badLeafTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(4),
		Subject:               pkix.Name{CommonName: "Bad Leaf"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(100, 0, 0),
		IsCA:                  false,
		BasicConstraintsValid: true,
		// IsCA:false — rejected because it is not a CA cert
	}
	badLeafPEM, _ := mustCreateCert(badLeafTmpl, caCert, &badLeafKey.PublicKey, caKey)

	fmt.Printf("Generating fixtures in %s/\n", outDir)

	writeFixture("valid-with-ca-cert.toml", buildFixture(map[string]string{
		"aa.toml":     innerTOML(aaToml(string(caPEM))),
		"cdh.toml":    innerTOML(cdhToml("")),
		"policy.rego": defaultPolicy,
	}))

	// invalid-leaf-cert.toml: a leaf (non-CA) cert in cdh.toml — must be rejected.
	writeFixture("invalid-leaf-cert.toml", buildFixture(map[string]string{
		"aa.toml":     innerTOML(aaToml("")),
		"cdh.toml":    innerTOML(cdhToml(string(leafPEM))),
		"policy.rego": defaultPolicy,
	}))

	// valid-with-both.toml: CA certs in both aa.toml and cdh.toml — must pass.
	writeFixture("valid-with-both.toml", buildFixture(map[string]string{
		"aa.toml":     innerTOML(aaToml(string(caPEM))),
		"cdh.toml":    innerTOML(cdhToml(string(ca2PEM))),
		"policy.rego": defaultPolicy,
	}))

	writeFixture("invalid-expired-cert.toml", buildFixture(map[string]string{
		"aa.toml":     innerTOML(aaToml(string(expPEM))),
		"cdh.toml":    innerTOML(cdhToml("")),
		"policy.rego": defaultPolicy,
	}))

	writeFixture("invalid-leaf-no-san.toml", buildFixture(map[string]string{
		"aa.toml":     innerTOML(aaToml(string(badLeafPEM))),
		"cdh.toml":    innerTOML(cdhToml("")),
		"policy.rego": defaultPolicy,
	}))

	fmt.Println("Done. Commit the new .toml files; the private keys were not written to disk.")
}
