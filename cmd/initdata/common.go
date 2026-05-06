// Package initdata provides the initdata subcommand group for cococtl.
package initdata

import (
	"bytes"
	"compress/gzip"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"strconv"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/confidential-devhub/cococtl/pkg/config"
	"github.com/pelletier/go-toml/v2"
)

func loadCerts(path string) ([]*x509.Certificate, error) {
	// #nosec G304 -- path comes from the user-provided --cacert flag
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", path, err)
	}
	return parsePEMCerts(data)
}

func loadCertsFromDir(dir string) ([]*x509.Certificate, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory %s: %w", dir, err)
	}
	var all []*x509.Certificate
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		// #nosec G304 -- path is constructed from the user-provided --capath directory
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("failed to read %s: %w", path, err)
		}
		certs, err := parsePEMCerts(data)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certs from %s: %w", path, err)
		}
		if len(certs) == 0 {
			fmt.Fprintf(os.Stderr, "skipping %s: no PEM blocks found\n", entry.Name())
			continue
		}
		all = append(all, certs...)
	}
	return all, nil
}

func parsePEMCerts(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for len(data) > 0 {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		data = rest
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %w", err)
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

// isSelfSigned reports whether cert was signed with its own key.
// Comparing RawIssuer and RawSubject is necessary but not sufficient — it only
// means the cert is self-issued. Verifying the signature confirms the cert
// actually signed itself, so a cert with a reused subject DN but a different
// issuer key is not falsely classified as self-signed.
func isSelfSigned(cert *x509.Certificate) bool {
	if !bytes.Equal(cert.RawIssuer, cert.RawSubject) {
		return false
	}
	return cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) == nil
}

// checkExpiry returns an error if cert is expired or not yet valid.
func checkExpiry(cert *x509.Certificate) error {
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return fmt.Errorf("certificate %q: not yet valid (valid from %s)", cert.Subject.CommonName, cert.NotBefore.Format("2006-01-02"))
	}
	if now.After(cert.NotAfter) {
		return fmt.Errorf("certificate %q: expired on %s", cert.Subject.CommonName, cert.NotAfter.Format("2006-01-02"))
	}
	return nil
}

// isWeakSignatureAlg reports whether alg is SHA-1, MD5, or MD2 — all rejected
// by rustls as insufficiently secure.
func isWeakSignatureAlg(alg x509.SignatureAlgorithm) bool {
	switch alg {
	case x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		return true
	}
	return false
}

// validateCACert checks that cert is a valid CA certificate: IsCA must be true,
// KeyUsageCertSign must be set, and the cert must not use weak crypto.
func validateCACert(cert *x509.Certificate) error {
	if !cert.IsCA {
		return fmt.Errorf("certificate %q: not a CA certificate (CA:TRUE required for trust anchors)", cert.Subject.CommonName)
	}
	if err := checkExpiry(cert); err != nil {
		return err
	}
	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return fmt.Errorf("certificate %q: missing KeyUsageCertSign", cert.Subject.CommonName)
	}
	if isWeakSignatureAlg(cert.SignatureAlgorithm) {
		return fmt.Errorf("certificate %q: weak signature algorithm %s", cert.Subject.CommonName, cert.SignatureAlgorithm)
	}
	if rsaKey, ok := cert.PublicKey.(*rsa.PublicKey); ok && rsaKey.N.BitLen() < 1024 {
		return fmt.Errorf("certificate %q: RSA key is %d bits, minimum is 1024", cert.Subject.CommonName, rsaKey.N.BitLen())
	}
	if len(cert.UnhandledCriticalExtensions) > 0 {
		oidStrs := make([]string, len(cert.UnhandledCriticalExtensions))
		for i, oid := range cert.UnhandledCriticalExtensions {
			parts := make([]string, len(oid))
			for j, n := range oid {
				parts[j] = strconv.Itoa(n)
			}
			oidStrs[i] = strings.Join(parts, ".")
		}
		return fmt.Errorf("certificate %q: has unknown critical extensions: %s",
			cert.Subject.CommonName, strings.Join(oidStrs, ", "))
	}
	return nil
}

// validateCACerts checks that every certificate in the slice satisfies CA
// requirements. Use this when the caller only expects CA certificates (e.g.
// the --cacert / --capath flags on the create command).
func validateCACerts(certs []*x509.Certificate) error {
	var errs []string
	for _, cert := range certs {
		if err := validateCACert(cert); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("cert validation failed:\n  %s", strings.Join(errs, "\n  "))
	}
	return nil
}

// validateCertsBySource applies CA certificate rules to each embedded cert and
// includes the source field in error messages so the user can locate the
// problematic cert. All initdata cert fields are trust anchor positions —
// only CA certificates (CA:TRUE, keyCertSign) are accepted.
func validateCertsBySource(entries []certEntry) error {
	var errs []string
	for _, e := range entries {
		if err := validateCACert(e.cert); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %s", e.source, err.Error()))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("cert validation failed:\n  %s", strings.Join(errs, "\n  "))
	}
	return nil
}

func certsToPEM(certs []*x509.Certificate) string {
	var sb strings.Builder
	for _, cert := range certs {
		_ = pem.Encode(&sb, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	}
	return sb.String()
}

func loadConfig(path string) (*config.CocoConfig, error) {
	if path == "" {
		var err error
		path, err = config.GetConfigPath()
		if err != nil {
			return nil, fmt.Errorf("failed to get default config path: %w", err)
		}
	}
	cfg, err := config.Load(path)
	if err != nil {
		return nil, fmt.Errorf("failed to load config from %s: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}
	return cfg, nil
}

func loadInitdataTOML(filePath string, r io.Reader) ([]byte, error) {
	if filePath != "" {
		// #nosec G304 -- path comes from the user-provided --file flag
		data, err := os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("failed to read %s: %w", filePath, err)
		}
		return data, nil
	}
	encoded, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read stdin: %w", err)
	}
	return decompressBlob(strings.TrimSpace(string(encoded)))
}

func decompressBlob(encoded string) ([]byte, error) {
	gzipData, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64: %w", err)
	}
	gr, err := gzip.NewReader(bytes.NewReader(gzipData))
	if err != nil {
		return nil, fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer func() { _ = gr.Close() }()
	data, err := io.ReadAll(gr)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress: %w", err)
	}
	return data, nil
}

// certEntry pairs a parsed certificate with its origin field within initdata.
type certEntry struct {
	cert   *x509.Certificate
	source string
}

func extractCertsFromInitdata(data map[string]string) ([]certEntry, error) {
	type pemSource struct {
		pem    string
		source string
	}
	var pemSources []pemSource

	if aaToml, ok := data["aa.toml"]; ok && aaToml != "" {
		var aa map[string]interface{}
		if err := toml.Unmarshal([]byte(aaToml), &aa); err != nil {
			return nil, fmt.Errorf("failed to parse aa.toml: %w", err)
		}
		if tc, ok := aa["token_configs"].(map[string]interface{}); ok {
			names := make([]string, 0, len(tc))
			for name := range tc {
				names = append(names, name)
			}
			sort.Strings(names)
			for _, name := range names {
				if entry, ok := tc[name].(map[string]interface{}); ok {
					if cert, ok := entry["cert"].(string); ok && cert != "" {
						pemSources = append(pemSources, pemSource{cert, "aa.toml/token_configs." + name})
					}
				}
			}
		}
	}

	if cdhToml, ok := data["cdh.toml"]; ok && cdhToml != "" {
		var cdh map[string]interface{}
		if err := toml.Unmarshal([]byte(cdhToml), &cdh); err != nil {
			return nil, fmt.Errorf("failed to parse cdh.toml: %w", err)
		}
		if kbc, ok := cdh["kbc"].(map[string]interface{}); ok {
			if cert, ok := kbc["kbs_cert"].(string); ok && cert != "" {
				pemSources = append(pemSources, pemSource{cert, "cdh.toml/kbc"})
			}
		}
		if img, ok := cdh["image"].(map[string]interface{}); ok {
			if extra, ok := img["extra_root_certificates"].([]interface{}); ok {
				for i, c := range extra {
					if cert, ok := c.(string); ok && cert != "" {
						pemSources = append(pemSources, pemSource{cert, fmt.Sprintf("cdh.toml/image.extra_root_certificates[%d]", i)})
					}
				}
			}
		}
	}

	// seen maps fingerprint to the index of the entry in all.
	// seenSources tracks which sources have already been recorded for each
	// fingerprint so that a cert appearing multiple times in the same PEM
	// bundle does not produce duplicate source labels.
	seen := make(map[string]int)
	seenSources := make(map[string]map[string]struct{})
	var all []certEntry
	for _, ps := range pemSources {
		certs, err := parsePEMCerts([]byte(ps.pem))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", ps.source, err)
		}
		for _, cert := range certs {
			fp := base64.StdEncoding.EncodeToString(cert.Raw)
			if _, dup := seen[fp]; !dup {
				seen[fp] = len(all)
				seenSources[fp] = map[string]struct{}{ps.source: {}}
				all = append(all, certEntry{cert: cert, source: ps.source})
			} else if _, srcSeen := seenSources[fp][ps.source]; !srcSeen {
				seenSources[fp][ps.source] = struct{}{}
				all[seen[fp]].source += ", " + ps.source
			}
		}
	}
	return all, nil
}
