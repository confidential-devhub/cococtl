package initdata

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"strings"
	"testing"

	"github.com/confidential-devhub/cococtl/pkg/config"
)

// minimalConfig returns a valid config for initdata generation (no file I/O).
func minimalConfig() *config.CocoConfig {
	cfg := config.DefaultConfig()
	cfg.TrusteeServer = "https://kbs.example.com"
	cfg.RuntimeClass = "kata-cc"
	return cfg
}

func TestGenerateWithArtifacts_ReturnsNonEmpty(t *testing.T) {
	cfg := minimalConfig()
	encoded, rawTOML, pcr8Hex, err := GenerateWithArtifacts(cfg, nil, cfg.TrusteeServer)
	if err != nil {
		t.Fatalf("GenerateWithArtifacts: %v", err)
	}
	if encoded == "" {
		t.Error("encoded is empty")
	}
	if rawTOML == "" {
		t.Error("rawTOML is empty")
	}
	if pcr8Hex == "" {
		t.Error("pcr8Hex is empty")
	}
	if len(pcr8Hex) != 64 {
		t.Errorf("pcr8Hex should be 64 hex chars, got %d", len(pcr8Hex))
	}
	if _, err := hex.DecodeString(pcr8Hex); err != nil {
		t.Errorf("pcr8Hex is not valid hex: %v", err)
	}
}

func TestGenerateWithArtifacts_PCR8Formula(t *testing.T) {
	cfg := minimalConfig()
	_, rawTOML, pcr8Hex, err := GenerateWithArtifacts(cfg, nil, cfg.TrusteeServer)
	if err != nil {
		t.Fatalf("GenerateWithArtifacts: %v", err)
	}
	tomlData := []byte(rawTOML)
	// PCR8 = SHA256(initial_pcr_32zeros || SHA256(tomlData))
	hash := sha256.Sum256(tomlData)
	var pcr8Input [64]byte
	copy(pcr8Input[32:], hash[:])
	pcr8 := sha256.Sum256(pcr8Input[:])
	wantPCR8 := hex.EncodeToString(pcr8[:])
	if pcr8Hex != wantPCR8 {
		t.Errorf("pcr8Hex = %s, want %s (PCR8 formula mismatch)", pcr8Hex, wantPCR8)
	}
}

func TestGenerateWithArtifacts_RawTOMLRoundTrips(t *testing.T) {
	cfg := minimalConfig()
	encoded, rawTOML, _, err := GenerateWithArtifacts(cfg, nil, cfg.TrusteeServer)
	if err != nil {
		t.Fatalf("GenerateWithArtifacts: %v", err)
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode base64: %v", err)
	}
	gz, err := gzip.NewReader(bytes.NewReader(decoded))
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	defer gz.Close()
	decompressed, err := io.ReadAll(gz)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(decompressed) != rawTOML {
		t.Error("decoded TOML does not match rawTOML (round-trip failed)")
	}
}

func TestGenerateWithArtifacts_MatchesGenerate(t *testing.T) {
	cfg := minimalConfig()
	encoded1, err := Generate(cfg, nil, cfg.TrusteeServer)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	encoded2, _, _, err := GenerateWithArtifacts(cfg, nil, cfg.TrusteeServer)
	if err != nil {
		t.Fatalf("GenerateWithArtifacts: %v", err)
	}
	if encoded1 != encoded2 {
		t.Error("Generate and GenerateWithArtifacts produced different encoded values")
	}
}

func TestGenerateWithArtifacts_EmptyTrusteeURL(t *testing.T) {
	cfg := minimalConfig()
	_, _, _, err := GenerateWithArtifacts(cfg, nil, "")
	if err == nil {
		t.Fatal("expected error for empty trustee URL")
	}
	if !strings.Contains(err.Error(), "trustee") {
		t.Errorf("error should mention trustee: %v", err)
	}
}

func TestGenerate_EmptyTrusteeURL(t *testing.T) {
	cfg := minimalConfig()
	_, err := Generate(cfg, nil, "")
	if err == nil {
		t.Fatal("expected error for empty trustee URL")
	}
	if !strings.Contains(err.Error(), "trustee") {
		t.Errorf("error should mention trustee: %v", err)
	}
}

func TestGenerateWithArtifacts_RawTOMLLayout(t *testing.T) {
	cfg := minimalConfig()
	_, rawTOML, _, err := GenerateWithArtifacts(cfg, nil, cfg.TrusteeServer)
	if err != nil {
		t.Fatalf("GenerateWithArtifacts: %v", err)
	}
	for _, want := range []string{
		`algorithm = "sha256"`,
		`version = "0.1.0"`,
		"[data]",
		`"aa.toml"`,
		`"cdh.toml"`,
		`"policy.rego"`,
		"https://kbs.example.com",
		"cc_kbc",
	} {
		if !strings.Contains(rawTOML, want) {
			t.Errorf("rawTOML missing %q", want)
		}
	}
}

func TestReplaceExtraRootCertificatesWithMultiline(t *testing.T) {
	certPEM := `-----BEGIN CERTIFICATE-----
MIIDaDCCAlCgAwIBAgIRAOvSL5qCBV2S5HQJ0aU3o0EwDQYJKoZIhvcNAQELBQAw
NzEPMA0GA1UECgwGbXlfb3JnMSQwIgYDVQQDExtrYnMtdHJ1c3RlZS1vcGVyYXRv
-----END CERTIFICATE-----
`
	// Simulate go-toml marshaled output (escaped newlines)
	tomlStr := `[image]
extra_root_certificates = ["-----BEGIN CERTIFICATE-----\nMIIDaDCCAlCgAwIBAgIRAOvSL5qCBV2S5HQJ0aU3o0EwDQYJKoZIhvcNAQELBQAw\nNzEPMA0GA1UECgwGbXlfb3JnMSQwIgYDVQQDExtrYnMtdHJ1c3RlZS1vcGVyYXRv\n-----END CERTIFICATE-----\n"]
`
	got := replaceExtraRootCertificatesWithMultiline(tomlStr, certPEM)

	// Must not contain escaped \n in the extra_root_certificates value (CDH expects real newlines)
	if idx := strings.Index(got, "extra_root_certificates"); idx >= 0 {
		section := got[idx:]
		if strings.Contains(section, `\n`) {
			t.Errorf("extra_root_certificates still has escaped \\n; use literal multi-line (\"\"\"):\n%s", got)
		}
	}
	// Must use TOML literal multi-line form
	if !strings.Contains(got, `"""`) {
		t.Errorf("output missing TOML literal multi-line (\"\"\"):\n%s", got)
	}
	if !strings.Contains(got, "-----BEGIN CERTIFICATE-----") || !strings.Contains(got, "-----END CERTIFICATE-----") {
		t.Errorf("output missing cert content:\n%s", got)
	}
}
