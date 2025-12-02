// Package certs provides certificate generation utilities for sidecar mTLS.
package certs

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

const (
	rsaKeySize        = 4096
	caValidityYears   = 2
	certValidityYears = 1
)

// CertificateSet holds a certificate and its private key in PEM format.
type CertificateSet struct {
	CertPEM []byte
	KeyPEM  []byte
}

// GenerateCA generates a new Certificate Authority.
// Returns the CA certificate and private key in PEM format.
func GenerateCA(commonName string) (*CertificateSet, error) {
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, rsaKeySize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA private key: %w", err)
	}

	// Prepare certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"Confidential Containers"},
			Country:      []string{"US"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(caValidityYears, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Create self-signed certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create CA certificate: %w", err)
	}

	// Encode to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	return &CertificateSet{
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
	}, nil
}

// SANs represents Subject Alternative Names for a certificate.
type SANs struct {
	DNSNames    []string
	IPAddresses []string
}

// GenerateServerCert generates a server certificate signed by the provided CA.
// The certificate includes the specified SANs for hostname/IP validation.
func GenerateServerCert(caCert, caKey []byte, commonName string, sans SANs) (*CertificateSet, error) {
	// Parse CA certificate
	caCertBlock, _ := pem.Decode(caCert)
	if caCertBlock == nil {
		return nil, fmt.Errorf("failed to decode CA certificate PEM")
	}
	caCertParsed, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	// Parse CA private key
	caKeyBlock, _ := pem.Decode(caKey)
	if caKeyBlock == nil {
		return nil, fmt.Errorf("failed to decode CA private key PEM")
	}
	caPrivateKey, err := x509.ParsePKCS1PrivateKey(caKeyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA private key: %w", err)
	}

	// Generate server private key
	privateKey, err := rsa.GenerateKey(rand.Reader, rsaKeySize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate server private key: %w", err)
	}

	// Prepare certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Parse IP addresses
	ipAddresses := make([]net.IP, 0, len(sans.IPAddresses))
	for _, ipStr := range sans.IPAddresses {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return nil, fmt.Errorf("invalid IP address: %s", ipStr)
		}
		ipAddresses = append(ipAddresses, ip)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"Confidential Containers"},
			Country:      []string{"US"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(certValidityYears, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              sans.DNSNames,
		IPAddresses:           ipAddresses,
	}

	// Create certificate signed by CA
	certDER, err := x509.CreateCertificate(rand.Reader, &template, caCertParsed, &privateKey.PublicKey, caPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create server certificate: %w", err)
	}

	// Encode to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	return &CertificateSet{
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
	}, nil
}

// GenerateClientCert generates a client certificate signed by the provided CA.
// Used for mTLS client authentication.
func GenerateClientCert(caCert, caKey []byte, commonName string) (*CertificateSet, error) {
	// Parse CA certificate
	caCertBlock, _ := pem.Decode(caCert)
	if caCertBlock == nil {
		return nil, fmt.Errorf("failed to decode CA certificate PEM")
	}
	caCertParsed, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	// Parse CA private key
	caKeyBlock, _ := pem.Decode(caKey)
	if caKeyBlock == nil {
		return nil, fmt.Errorf("failed to decode CA private key PEM")
	}
	caPrivateKey, err := x509.ParsePKCS1PrivateKey(caKeyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA private key: %w", err)
	}

	// Generate client private key
	privateKey, err := rsa.GenerateKey(rand.Reader, rsaKeySize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate client private key: %w", err)
	}

	// Prepare certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"Confidential Containers"},
			Country:      []string{"US"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(certValidityYears, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	// Create certificate signed by CA
	certDER, err := x509.CreateCertificate(rand.Reader, &template, caCertParsed, &privateKey.PublicKey, caPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create client certificate: %w", err)
	}

	// Encode to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	return &CertificateSet{
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
	}, nil
}

// SaveToFile saves a certificate set to files in the specified directory.
// Files are created with strict permissions (0600) to protect cryptographic material.
// Note: Uses os.OpenFile with explicit mode to bypass umask.
func (cs *CertificateSet) SaveToFile(dir, baseName string) error {
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	certPath := filepath.Join(dir, baseName+"-cert.pem")
	keyPath := filepath.Join(dir, baseName+"-key.pem")

	// Use OpenFile with O_CREATE to ensure exact permissions regardless of umask
	if err := writeFileSecure(certPath, cs.CertPEM); err != nil {
		return fmt.Errorf("failed to write certificate to %s: %w", certPath, err)
	}

	if err := writeFileSecure(keyPath, cs.KeyPEM); err != nil {
		return fmt.Errorf("failed to write private key to %s: %w", keyPath, err)
	}

	return nil
}

// writeFileSecure writes data to file with strict 0600 permissions.
// Uses os.OpenFile to bypass umask and ensure exact permissions.
func writeFileSecure(path string, data []byte) error {
	// O_WRONLY|O_CREATE|O_TRUNC: write-only, create if not exists, truncate if exists
	// 0600: read/write for owner only, regardless of umask
	// #nosec G304 -- Path is constructed from trusted baseName parameter in SaveToFile
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := f.Close(); closeErr != nil {
			// Log close error but don't override primary error
			fmt.Fprintf(os.Stderr, "Warning: failed to close file %s: %v\n", path, closeErr)
		}
	}()

	if _, err := f.Write(data); err != nil {
		return err
	}

	// Explicitly chmod to ensure permissions are set correctly
	if err := f.Chmod(0600); err != nil {
		return err
	}

	return nil
}
