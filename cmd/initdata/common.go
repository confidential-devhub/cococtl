// Package initdata provides the initdata subcommand group for cococtl.
package initdata

import (
	"bytes"
	"compress/gzip"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

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

func validateCACert(cert *x509.Certificate) error {
	if !cert.IsCA {
		return fmt.Errorf("certificate %q: IsCA is false", cert.Subject.CommonName)
	}
	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return fmt.Errorf("certificate %q: missing KeyUsageCertSign", cert.Subject.CommonName)
	}
	return nil
}

func validateCerts(certs []*x509.Certificate) error {
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

func extractCertsFromInitdata(data map[string]string) ([]*x509.Certificate, error) {
	var pemStrings []string

	if aaToml, ok := data["aa.toml"]; ok && aaToml != "" {
		var aa map[string]interface{}
		if err := toml.Unmarshal([]byte(aaToml), &aa); err != nil {
			return nil, fmt.Errorf("failed to parse aa.toml: %w", err)
		}
		if tc, ok := aa["token_configs"].(map[string]interface{}); ok {
			for _, v := range tc {
				if entry, ok := v.(map[string]interface{}); ok {
					if cert, ok := entry["cert"].(string); ok && cert != "" {
						pemStrings = append(pemStrings, cert)
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
				pemStrings = append(pemStrings, cert)
			}
		}
		if img, ok := cdh["image"].(map[string]interface{}); ok {
			if extra, ok := img["extra_root_certificates"].([]interface{}); ok {
				for _, c := range extra {
					if cert, ok := c.(string); ok && cert != "" {
						pemStrings = append(pemStrings, cert)
					}
				}
			}
		}
	}

	seen := make(map[string]bool)
	var all []*x509.Certificate
	for _, pemStr := range pemStrings {
		certs, err := parsePEMCerts([]byte(pemStr))
		if err != nil {
			return nil, err
		}
		for _, cert := range certs {
			fp := base64.StdEncoding.EncodeToString(cert.Raw)
			if !seen[fp] {
				seen[fp] = true
				all = append(all, cert)
			}
		}
	}
	return all, nil
}
