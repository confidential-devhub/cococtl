package initdata

import (
	"strings"
	"testing"
)

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
