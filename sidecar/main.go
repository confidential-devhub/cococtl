// CoCo Secure Access Sidecar provides mTLS-secured HTTPS access to confidential pods
package main

import (
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/confidential-devhub/cococtl/sidecar/pkg/certs"
	"github.com/confidential-devhub/cococtl/sidecar/pkg/server"
	"github.com/confidential-devhub/cococtl/sidecar/pkg/status"
)

func main() {
	log.Println("Starting CoCo Secure Access Sidecar...")

	config := readConfig()

	// Fetch TLS certificates and Client CA from CDH/KBS
	log.Println("Fetching certificates from KBS via CDH...")
	tlsCert, tlsKey, clientCA, err := certs.FetchAllCerts(
		config.TLSCertURI,
		config.TLSKeyURI,
		config.ClientCAURI,
	)
	if err != nil {
		log.Fatalf("Failed to fetch certificates: %v", err)
	}
	log.Println("Successfully fetched all certificates from KBS")

	// Initialize status collector
	statusCollector := status.NewCollector()

	// Start HTTPS server with mTLS
	log.Printf("Starting HTTPS server with mTLS on port %d...", config.HTTPSPort)
	httpsServer := server.NewHTTPSServer(
		config.HTTPSPort,
		tlsCert,
		tlsKey,
		clientCA,
		statusCollector,
		config.ForwardPort,
	)
	if err := httpsServer.Start(); err != nil {
		log.Fatalf("HTTPS server failed: %v", err)
	}
}

// Config represents the sidecar configuration
type Config struct {
	HTTPSPort   int
	TLSCertURI  string
	TLSKeyURI   string
	ClientCAURI string
	ForwardPort int
}

func readConfig() *Config {
	httpsPort, _ := strconv.Atoi(getEnvOrDefault("HTTPS_PORT", "8443"))
	log.Printf("Configuration: HTTPS port set to %d", httpsPort)

	forwardPort := 0
	if portStr := os.Getenv("FORWARD_PORT"); portStr != "" {
		if port, err := strconv.Atoi(strings.TrimSpace(portStr)); err == nil {
			forwardPort = port
			log.Printf("Configuration: Forward port configured: %d", forwardPort)
		} else {
			log.Printf("WARNING: Invalid FORWARD_PORT value: %s", portStr)
		}
	} else {
		log.Println("Configuration: No forward port configured")
	}

	tlsCertURI := os.Getenv("TLS_CERT_URI")
	tlsKeyURI := os.Getenv("TLS_KEY_URI")
	clientCAURI := os.Getenv("CLIENT_CA_URI")

	if tlsCertURI != "" {
		log.Printf("Configuration: TLS_CERT_URI set")
	} else {
		log.Println("WARNING: TLS_CERT_URI not set")
	}

	if tlsKeyURI != "" {
		log.Printf("Configuration: TLS_KEY_URI set")
	} else {
		log.Println("WARNING: TLS_KEY_URI not set")
	}

	if clientCAURI != "" {
		log.Printf("Configuration: CLIENT_CA_URI set")
	} else {
		log.Println("WARNING: CLIENT_CA_URI not set")
	}

	return &Config{
		HTTPSPort:   httpsPort,
		TLSCertURI:  tlsCertURI,
		TLSKeyURI:   tlsKeyURI,
		ClientCAURI: clientCAURI,
		ForwardPort: forwardPort,
	}
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
