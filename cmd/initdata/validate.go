package initdata

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	pkginitdata "github.com/confidential-devhub/cococtl/pkg/initdata"
	"github.com/pelletier/go-toml/v2"
	"github.com/spf13/cobra"
)

// errValidationFailed is a sentinel returned when runValidate has already
// printed its own diagnostics and wants a non-zero exit without Cobra
// printing an additional "Error: ..." line.
var errValidationFailed = errors.New("")

var validateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate initdata structure and embedded certificates",
	Long: `Validate an initdata for structural correctness and certificate validity.

Reads from --file (plaintext TOML) or stdin (base64+gzip encoded blob).

Checks:
  - TOML parses cleanly
  - version == "0.1.0" and algorithm is one of sha256, sha384, sha512
  - aa.toml and cdh.toml are present (policy.rego is optional)
  - Embedded certs are CA certificates (CA:TRUE, keyCertSign key usage)

Rejected certs: leaf/non-CA certificates, expired certs, SHA-1 or MD5
signatures, unknown critical extensions, RSA keys shorter than 1024 bits.

Exit codes: 0 = passed, 1 = validation failed or input error.

Examples:
  kubectl coco initdata validate --file ~/.kube/coco-initdata.toml
  kubectl coco initdata dump | kubectl coco initdata validate`,
	RunE: runValidate,
}

var validateFile string

func init() {
	validateCmd.Flags().StringVar(&validateFile, "file", "", "Path to plaintext initdata TOML file (reads encoded blob from stdin if not set)")
}

// silenceAndReturn silences Cobra's own error/usage output for this command
// and returns the sentinel. Call only after writing diagnostics to stderr.
// cmd may be nil when runValidate is called directly in tests.
func silenceAndReturn(cmd *cobra.Command) error {
	if cmd != nil {
		cmd.SilenceErrors = true
		cmd.SilenceUsage = true
	}
	return errValidationFailed
}

func runValidate(cmd *cobra.Command, _ []string) error {
	tomlBytes, err := loadInitdataTOML(validateFile, os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to load initdata: %v\n", err)
		return silenceAndReturn(cmd)
	}

	var id pkginitdata.InitData
	if err := toml.Unmarshal(tomlBytes, &id); err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to parse TOML: %v\n", err)
		return silenceAndReturn(cmd)
	}

	var failures []string

	if id.Version != pkginitdata.InitDataVersion {
		failures = append(failures, fmt.Sprintf("version: got %q, want %q", id.Version, pkginitdata.InitDataVersion))
	}
	if !pkginitdata.IsValidAlgorithm(id.Algorithm) {
		failures = append(failures, fmt.Sprintf("algorithm: got %q, want one of %v", id.Algorithm, pkginitdata.ValidAlgorithms))
	}
	for _, key := range []string{"aa.toml", "cdh.toml"} {
		if _, ok := id.Data[key]; !ok {
			failures = append(failures, fmt.Sprintf("missing required data key: %s", key))
		}
	}

	if warn := checkKBSURLMismatch(id.Data); warn != "" {
		fmt.Fprint(os.Stderr, warn)
	}

	entries, err := extractCertsFromInitdata(id.Data)
	if err != nil {
		failures = append(failures, fmt.Sprintf("cert extraction failed: %v", err))
	} else if len(entries) > 0 {
		reportCerts(entries)
		if err := validateCertsBySource(entries); err != nil {
			failures = append(failures, err.Error())
		}
	}

	if len(failures) > 0 {
		fmt.Fprintln(os.Stderr, "Validation failed:")
		for _, f := range failures {
			fmt.Fprintf(os.Stderr, "  %s\n", f)
		}
		return silenceAndReturn(cmd)
	}

	fmt.Println("Validation passed.")
	return nil
}

// checkKBSURLMismatch returns a warning message when KBS URLs differ across
// the aa.toml token_configs and cdh.toml kbc entries, or an empty string if
// all URLs are consistent. Differing URLs are valid but likely unintentional.
func checkKBSURLMismatch(data map[string]string) string {
	type urlEntry struct {
		source string
		url    string
	}

	// normalizeURL strips trailing slashes and whitespace so that
	// "https://kbs:8080" and "https://kbs:8080/" are treated as equal.
	normalizeURL := func(u string) string {
		return strings.TrimRight(strings.TrimSpace(u), "/")
	}

	var entries []urlEntry

	if aaToml, ok := data["aa.toml"]; ok && aaToml != "" {
		var aa map[string]interface{}
		if err := toml.Unmarshal([]byte(aaToml), &aa); err == nil {
			if tc, ok := aa["token_configs"].(map[string]interface{}); ok {
				names := make([]string, 0, len(tc))
				for name := range tc {
					names = append(names, name)
				}
				sort.Strings(names)
				for _, name := range names {
					if entry, ok := tc[name].(map[string]interface{}); ok {
						if url, ok := entry["url"].(string); ok && url != "" {
							entries = append(entries, urlEntry{"aa.toml/token_configs." + name, normalizeURL(url)})
						}
					}
				}
			}
		}
	}

	if cdhToml, ok := data["cdh.toml"]; ok && cdhToml != "" {
		var cdh map[string]interface{}
		if err := toml.Unmarshal([]byte(cdhToml), &cdh); err == nil {
			if kbc, ok := cdh["kbc"].(map[string]interface{}); ok {
				if url, ok := kbc["url"].(string); ok && url != "" {
					entries = append(entries, urlEntry{"cdh.toml/kbc", normalizeURL(url)})
				}
			}
		}
	}

	if len(entries) < 2 {
		return ""
	}

	sort.Slice(entries, func(i, j int) bool { return entries[i].source < entries[j].source })

	first := entries[0].url
	for _, e := range entries[1:] {
		if e.url != first {
			var sb strings.Builder
			sb.WriteString("WARNING: KBS URLs differ across configurations — verify this is intentional:\n")
			for _, e := range entries {
				fmt.Fprintf(&sb, "  %-44s %s\n", e.source+":", e.url)
			}
			sb.WriteByte('\n')
			return sb.String()
		}
	}
	return ""
}

func reportCerts(entries []certEntry) {
	caCount, leafCount := 0, 0
	for _, e := range entries {
		if e.cert.IsCA {
			caCount++
		} else {
			leafCount++
		}
	}
	fmt.Printf("Certificates: %d total  (%d CA, %d leaf)\n\n", len(entries), caCount, leafCount)

	for i, e := range entries {
		cert := e.cert
		selfSigned := isSelfSigned(cert)

		typeLabel := "leaf"
		if cert.IsCA {
			typeLabel = "CA"
		}
		if selfSigned {
			typeLabel += " · self-signed"
		}

		issuerCN := cert.Issuer.CommonName
		if issuerCN == "" {
			issuerCN = cert.Issuer.String()
		}

		fp := sha256.Sum256(cert.Raw)
		fingerprint := fmt.Sprintf("%X", fp[:6]) // first 6 bytes for brevity

		fmt.Printf("  [%d] %s  [%s]\n", i+1, certDisplayName(cert), typeLabel)
		fmt.Printf("      %-12s %s\n", "Issuer:", issuerCN)
		fmt.Printf("      %-12s %s → %s  (%s)\n", "Valid:", cert.NotBefore.Format("2006-01-02"), cert.NotAfter.Format("2006-01-02"), certExpiryNote(cert))
		fmt.Printf("      %-12s %s\n", "Key:", certKeyDesc(cert.PublicKey))
		if usage := certFormatKeyUsage(cert.KeyUsage); usage != "" {
			fmt.Printf("      %-12s %s\n", "Usage:", usage)
		}
		if !cert.IsCA {
			if san := certFormatSANs(cert); san != "" {
				fmt.Printf("      %-12s %s\n", "SAN:", san)
			}
		}
		if eku := certFormatEKU(cert.ExtKeyUsage); eku != "" {
			fmt.Printf("      %-12s %s\n", "EKU:", eku)
		}
		fmt.Printf("      %-12s %s\n", "Fingerprint:", fingerprint)
		fmt.Printf("      %-12s %s\n", "Source:", e.source)
		fmt.Println()
	}
}

// certDisplayName returns a human-readable identifier for cert. It prefers the
// Common Name, but falls back to the first SAN when CN is empty (as is common
// for modern server certificates).
func certDisplayName(cert *x509.Certificate) string {
	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName
	}
	if len(cert.DNSNames) > 0 {
		return cert.DNSNames[0]
	}
	if len(cert.IPAddresses) > 0 {
		return cert.IPAddresses[0].String()
	}
	if len(cert.URIs) > 0 {
		return cert.URIs[0].String()
	}
	fp := sha256.Sum256(cert.Raw)
	return fmt.Sprintf("(no CN) %X", fp[:6])
}

func certExpiryNote(cert *x509.Certificate) string {
	now := time.Now()
	if now.After(cert.NotAfter) {
		days := int(now.Sub(cert.NotAfter).Hours() / 24)
		return fmt.Sprintf("EXPIRED %d days ago", days)
	}
	days := int(cert.NotAfter.Sub(now).Hours() / 24)
	if days < 30 {
		return fmt.Sprintf("%d days remaining — WARNING", days)
	}
	return fmt.Sprintf("%d days remaining", days)
}

func certKeyDesc(pub interface{}) string {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA-%d", k.N.BitLen())
	case *ecdsa.PublicKey:
		return fmt.Sprintf("ECDSA %s", k.Curve.Params().Name)
	case ed25519.PublicKey:
		return "Ed25519"
	default:
		return "unknown"
	}
}

func certFormatKeyUsage(u x509.KeyUsage) string {
	type flag struct {
		bit  x509.KeyUsage
		name string
	}
	flags := []flag{
		{x509.KeyUsageCertSign, "CertSign"},
		{x509.KeyUsageCRLSign, "CRLSign"},
		{x509.KeyUsageDigitalSignature, "DigitalSignature"},
		{x509.KeyUsageKeyEncipherment, "KeyEncipherment"},
		{x509.KeyUsageContentCommitment, "ContentCommitment"},
		{x509.KeyUsageKeyAgreement, "KeyAgreement"},
		{x509.KeyUsageDataEncipherment, "DataEncipherment"},
		{x509.KeyUsageEncipherOnly, "EncipherOnly"},
		{x509.KeyUsageDecipherOnly, "DecipherOnly"},
	}
	var parts []string
	for _, f := range flags {
		if u&f.bit != 0 {
			parts = append(parts, f.name)
		}
	}
	return strings.Join(parts, ", ")
}

func certFormatEKU(ekus []x509.ExtKeyUsage) string {
	names := map[x509.ExtKeyUsage]string{
		x509.ExtKeyUsageServerAuth:      "serverAuth",
		x509.ExtKeyUsageClientAuth:      "clientAuth",
		x509.ExtKeyUsageCodeSigning:     "codeSigning",
		x509.ExtKeyUsageEmailProtection: "emailProtection",
		x509.ExtKeyUsageTimeStamping:    "timeStamping",
		x509.ExtKeyUsageOCSPSigning:     "OCSPSigning",
	}
	var parts []string
	for _, eku := range ekus {
		if name, ok := names[eku]; ok {
			parts = append(parts, name)
		} else {
			parts = append(parts, fmt.Sprintf("unknown(%d)", eku))
		}
	}
	return strings.Join(parts, ", ")
}

func certFormatSANs(cert *x509.Certificate) string {
	parts := make([]string, 0, len(cert.DNSNames)+len(cert.IPAddresses)+len(cert.URIs)+len(cert.EmailAddresses))
	for _, d := range cert.DNSNames {
		parts = append(parts, "DNS:"+d)
	}
	for _, ip := range cert.IPAddresses {
		parts = append(parts, "IP:"+ip.String())
	}
	for _, u := range cert.URIs {
		parts = append(parts, "URI:"+u.String())
	}
	for _, e := range cert.EmailAddresses {
		parts = append(parts, "email:"+e)
	}
	return strings.Join(parts, "  ")
}
