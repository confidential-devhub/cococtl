package initdata

import (
	"os"
	"strings"
	"testing"

	"github.com/confidential-devhub/cococtl/pkg/config"
	"github.com/pelletier/go-toml/v2"
)

func minimalCfg() *config.CocoConfig {
	return &config.CocoConfig{
		TrusteeServer: "http://kbs.test.svc:8080",
		RuntimeClass:  "kata-cc",
	}
}

func TestGenerateRaw_ReturnsValidTOML(t *testing.T) {
	raw, err := GenerateRaw(minimalCfg(), "", nil)
	if err != nil {
		t.Fatalf("GenerateRaw() error: %v", err)
	}
	var id InitData
	if err := toml.Unmarshal(raw, &id); err != nil {
		t.Fatalf("output is not valid TOML: %v", err)
	}
	if id.Version != InitDataVersion {
		t.Errorf("version = %q, want %q", id.Version, InitDataVersion)
	}
	if id.Algorithm != InitDataAlgorithm {
		t.Errorf("algorithm = %q, want %q", id.Algorithm, InitDataAlgorithm)
	}
	for _, key := range []string{"aa.toml", "cdh.toml", "policy.rego"} {
		if _, ok := id.Data[key]; !ok {
			t.Errorf("data[%q] missing", key)
		}
	}
}

func TestGenerateRaw_WithCertPEM(t *testing.T) {
	const fakePEM = "FAKECERT"
	raw, err := GenerateRaw(minimalCfg(), fakePEM, nil)
	if err != nil {
		t.Fatalf("GenerateRaw() error: %v", err)
	}
	if !strings.Contains(string(raw), fakePEM) {
		t.Error("cert PEM not found in raw output")
	}
}

func TestGenerateRaw_NoCert_Succeeds(t *testing.T) {
	raw, err := GenerateRaw(minimalCfg(), "", nil)
	if err != nil {
		t.Fatalf("GenerateRaw() error: %v", err)
	}
	if len(raw) == 0 {
		t.Error("expected non-empty output")
	}
}

func TestGenerateRaw_ReadsCertFromFile(t *testing.T) {
	const fakePEM = "FILECERT"
	f, err := os.CreateTemp(t.TempDir(), "ca-*.pem")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(fakePEM); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	cfg := minimalCfg()
	cfg.TrusteeCACert = f.Name()

	raw, err := GenerateRaw(cfg, "", nil)
	if err != nil {
		t.Fatalf("GenerateRaw() error: %v", err)
	}
	if !strings.Contains(string(raw), fakePEM) {
		t.Error("cert read from file not found in raw output")
	}
}

func TestGenerateRaw_RequiresTrusteeServer(t *testing.T) {
	_, err := GenerateRaw(&config.CocoConfig{}, "", nil)
	if err == nil {
		t.Fatal("expected error for empty TrusteeServer")
	}
}

func TestGenerate_StillWorks(t *testing.T) {
	encoded, err := Generate(minimalCfg(), nil)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	if encoded == "" {
		t.Error("Generate() returned empty string")
	}
}

func TestDecode_RoundTrip(t *testing.T) {
	encoded, err := Generate(minimalCfg(), nil)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	data, err := Decode(encoded)
	if err != nil {
		t.Fatalf("Decode() error: %v", err)
	}
	for _, key := range []string{"aa.toml", "cdh.toml", "policy.rego"} {
		if _, ok := data[key]; !ok {
			t.Errorf("Decode() missing key %q", key)
		}
	}
}

func TestDecode_InvalidBase64(t *testing.T) {
	_, err := Decode("not-valid-base64!!!")
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
}
