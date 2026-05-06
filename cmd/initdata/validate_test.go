package initdata

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"io"
	"os"
	"strings"
	"testing"
)

// runValidateStderr runs runValidate and returns stderr output alongside the error.
// Use this for tests that check validation failure messages.
func runValidateStderr(t *testing.T) (string, error) {
	t.Helper()
	r, w, pipeErr := os.Pipe()
	if pipeErr != nil {
		t.Fatalf("os.Pipe: %v", pipeErr)
	}
	oldStderr := os.Stderr
	os.Stderr = w
	t.Cleanup(func() { os.Stderr = oldStderr })
	err := runValidate(nil, nil)
	_ = w.Close()
	out, _ := io.ReadAll(r)
	_ = r.Close()
	return string(out), err
}

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

	stderr, err := runValidateStderr(t)
	if err == nil || !strings.Contains(stderr, "version") {
		t.Errorf("expected version error in stderr, got err=%v stderr=%q", err, stderr)
	}
}

func TestRunValidate_WrongAlgorithm(t *testing.T) {
	validateFile = "testdata/invalid-algorithm.toml"
	defer func() { validateFile = "" }()

	stderr, err := runValidateStderr(t)
	if err == nil || !strings.Contains(stderr, "algorithm") {
		t.Errorf("expected algorithm error in stderr, got err=%v stderr=%q", err, stderr)
	}
}

func TestRunValidate_MissingRequiredKey(t *testing.T) {
	validateFile = "testdata/invalid-missing-cdh.toml"
	defer func() { validateFile = "" }()

	stderr, err := runValidateStderr(t)
	if err == nil || !strings.Contains(stderr, "cdh.toml") {
		t.Errorf("expected missing cdh.toml in stderr, got err=%v stderr=%q", err, stderr)
	}
}

func TestRunValidate_WithCACert(t *testing.T) {
	validateFile = "testdata/valid-with-ca-cert.toml"
	defer func() { validateFile = "" }()
	if err := runValidate(nil, nil); err != nil {
		t.Errorf("runValidate() with CA cert fixture: %v", err)
	}
}

// TestRunValidate_LeafCertRejected uses a cert with valid SAN and serverAuth EKU
// — a cert that would have passed the old leaf-cert rules — to confirm that even
// a "well-formed" leaf cert is rejected when used as a trust anchor.
func TestRunValidate_LeafCertRejected(t *testing.T) {
	validateFile = "testdata/invalid-leaf-cert.toml"
	defer func() { validateFile = "" }()
	stderr, err := runValidateStderr(t)
	if err == nil || !strings.Contains(stderr, "not a CA certificate") {
		t.Errorf("runValidate() should reject leaf cert, got err=%v stderr=%q", err, stderr)
	}
}

func TestRunValidate_WithBothCACerts(t *testing.T) {
	validateFile = "testdata/valid-with-both.toml"
	defer func() { validateFile = "" }()
	if err := runValidate(nil, nil); err != nil {
		t.Errorf("runValidate() with two CA cert fixture: %v", err)
	}
}

func TestRunValidate_InvalidEmbeddedCert(t *testing.T) {
	validateFile = "testdata/invalid-leaf-no-san.toml"
	defer func() { validateFile = "" }()
	stderr, err := runValidateStderr(t)
	if err == nil || !strings.Contains(stderr, "not a CA certificate") {
		t.Errorf("expected 'not a CA certificate' in stderr, got err=%v stderr=%q", err, stderr)
	}
}

func TestRunValidate_ExpiredCertFixture(t *testing.T) {
	validateFile = "testdata/invalid-expired-cert.toml"
	defer func() { validateFile = "" }()
	stderr, err := runValidateStderr(t)
	if err == nil || !strings.Contains(stderr, "expired") {
		t.Errorf("expected 'expired' in stderr, got err=%v stderr=%q", err, stderr)
	}
}

func makeValidateTOML(t *testing.T, algorithm string) string {
	t.Helper()
	return `version = "0.1.0"
algorithm = "` + algorithm + `"

[data]
"aa.toml" = '''
[token_configs]
[token_configs.kbs]
url = "http://kbs.example.svc:8080"
'''
"cdh.toml" = '''
[kbc]
name = "cc_kbc"
url = "http://kbs.example.svc:8080"
'''
`
}

func TestRunValidate_SHA384Accepted(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/initdata.toml"
	_ = os.WriteFile(path, []byte(makeValidateTOML(t, "sha384")), 0600)
	validateFile = path
	defer func() { validateFile = "" }()
	if err := runValidate(nil, nil); err != nil {
		t.Errorf("sha384 algorithm should be accepted, got: %v", err)
	}
}

func TestRunValidate_SHA512Accepted(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/initdata.toml"
	_ = os.WriteFile(path, []byte(makeValidateTOML(t, "sha512")), 0600)
	validateFile = path
	defer func() { validateFile = "" }()
	if err := runValidate(nil, nil); err != nil {
		t.Errorf("sha512 algorithm should be accepted, got: %v", err)
	}
}

func TestRunValidate_URLMismatchGoesToStderr(t *testing.T) {
	toml := `version = "0.1.0"
algorithm = "sha256"

[data]
"aa.toml" = '''
[token_configs]
[token_configs.kbs]
url = "http://kbs1.svc:8080"
cert = "PLACEHOLDER"
'''
"cdh.toml" = '''
[kbc]
name = "cc_kbc"
url = "http://kbs2.svc:8080"
'''
`
	dir := t.TempDir()
	path := dir + "/initdata.toml"
	_ = os.WriteFile(path, []byte(toml), 0600)
	validateFile = path
	defer func() { validateFile = "" }()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	oldStderr := os.Stderr
	os.Stderr = w
	t.Cleanup(func() { os.Stderr = oldStderr })

	runErr := runValidate(nil, nil)

	_ = w.Close()
	stderrOut, _ := io.ReadAll(r)
	_ = r.Close()

	if runErr != nil {
		t.Errorf("runValidate() unexpected error: %v", runErr)
	}
	if !strings.Contains(string(stderrOut), "WARNING") {
		t.Errorf("URL mismatch warning should appear on stderr, got stdout-only output; stderr was: %q", string(stderrOut))
	}
}

// certBearingEntry returns a token_configs.kbs TOML fragment with a non-empty
// cert field, which is what checkKBSURLMismatch uses to identify KBS entries.
func certBearingEntry(url string) string {
	return "[token_configs]\n[token_configs.kbs]\nurl = \"" + url + "\"\ncert = \"PLACEHOLDER\"\n"
}

func TestCheckKBSURLMismatch_TrailingSlash(t *testing.T) {
	data := map[string]string{
		"aa.toml":  certBearingEntry("http://kbs.svc:8080"),
		"cdh.toml": "[kbc]\nname = \"cc_kbc\"\nurl = \"http://kbs.svc:8080/\"\n",
	}
	if msg := checkKBSURLMismatch(data); msg != "" {
		t.Errorf("trailing slash should not trigger a mismatch warning, got: %s", msg)
	}
}

func TestCheckKBSURLMismatch_SameURL(t *testing.T) {
	data := map[string]string{
		"aa.toml":  certBearingEntry("http://kbs.svc:8080"),
		"cdh.toml": "[kbc]\nname = \"cc_kbc\"\nurl = \"http://kbs.svc:8080\"\n",
	}
	if msg := checkKBSURLMismatch(data); msg != "" {
		t.Errorf("expected no warning for matching URLs, got: %s", msg)
	}
}

func TestCheckKBSURLMismatch_DifferentURLs(t *testing.T) {
	data := map[string]string{
		"aa.toml":  certBearingEntry("http://kbs1.svc:8080"),
		"cdh.toml": "[kbc]\nname = \"cc_kbc\"\nurl = \"http://kbs2.svc:8080\"\n",
	}
	msg := checkKBSURLMismatch(data)
	if msg == "" {
		t.Fatal("expected warning for different URLs")
	}
	if !strings.Contains(msg, "WARNING") {
		t.Errorf("expected WARNING prefix, got: %s", msg)
	}
	if !strings.Contains(msg, "kbs1.svc") || !strings.Contains(msg, "kbs2.svc") {
		t.Errorf("expected both URLs in message, got: %s", msg)
	}
}

func TestCheckKBSURLMismatch_SingleSource(t *testing.T) {
	data := map[string]string{
		"aa.toml":  certBearingEntry("http://kbs.svc:8080"),
		"cdh.toml": "[kbc]\nname = \"cc_kbc\"\n",
	}
	if msg := checkKBSURLMismatch(data); msg != "" {
		t.Errorf("expected no warning with only one URL source, got: %s", msg)
	}
}

func TestCheckKBSURLMismatch_MultipleTokenConfigs(t *testing.T) {
	// Two cert-bearing token_config entries with different URLs — should warn.
	data := map[string]string{
		"aa.toml": "[token_configs]\n" +
			"[token_configs.kbs1]\nurl = \"http://kbs1.svc:8080\"\ncert = \"PLACEHOLDER\"\n" +
			"[token_configs.kbs2]\nurl = \"http://kbs2.svc:8080\"\ncert = \"PLACEHOLDER\"\n",
		"cdh.toml": "[kbc]\nname = \"cc_kbc\"\nurl = \"http://kbs1.svc:8080\"\n",
	}
	msg := checkKBSURLMismatch(data)
	if msg == "" {
		t.Fatal("expected warning when token_configs have different URLs")
	}
	if !strings.Contains(msg, "kbs2.svc") {
		t.Errorf("expected differing URL in message, got: %s", msg)
	}
}

func TestCheckKBSURLMismatch_AllTokenConfigsCompared(t *testing.T) {
	// All token_configs URL entries are compared regardless of whether they
	// have a cert field — a coco_as entry pointing at a different endpoint
	// is still worth warning about so the user can verify intent.
	data := map[string]string{
		"aa.toml": "[token_configs]\n" +
			"[token_configs.kbs]\nurl = \"http://kbs.svc:8080\"\ncert = \"PLACEHOLDER\"\n" +
			"[token_configs.coco_as]\nurl = \"http://other.svc:9090\"\n",
		"cdh.toml": "[kbc]\nname = \"cc_kbc\"\nurl = \"http://kbs.svc:8080\"\n",
	}
	msg := checkKBSURLMismatch(data)
	if msg == "" {
		t.Fatal("expected warning: all token_configs URLs are compared, including non-KBS entries")
	}
	if !strings.Contains(msg, "other.svc") {
		t.Errorf("expected differing URL in warning, got: %s", msg)
	}
}

func TestReportCerts_Output(t *testing.T) {
	ca1, _, _ := makeTestCACert(t)
	ca2, _, _ := makeTestCACert(t)
	entries := []certEntry{
		{cert: ca1, source: "aa.toml/token_configs.kbs"},
		{cert: ca2, source: "cdh.toml/kbc"},
	}

	var buf bytes.Buffer
	if err := reportCerts(&buf, entries); err != nil {
		t.Fatalf("reportCerts() unexpected error: %v", err)
	}
	output := buf.String()
	checks := []struct {
		label string
		want  string
	}{
		{"summary line", "2 total"},
		{"CA count", "2 CA"},
		{"leaf count", "0 leaf"},
		{"CA subject", "Test CA"},
		{"CA type label", "[CA"},
		{"source aa", "aa.toml/token_configs.kbs"},
		{"source cdh", "cdh.toml/kbc"},
		{"key type", "RSA-"},
		{"fingerprint label", "Fingerprint:"},
	}
	for _, c := range checks {
		if !strings.Contains(output, c.want) {
			t.Errorf("reportCerts output missing %s (%q);\nfull output:\n%s", c.label, c.want, output)
		}
	}
}
