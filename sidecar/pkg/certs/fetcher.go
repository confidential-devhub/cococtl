// Package certs provides certificate fetching functionality from CDH/KBS
package certs

import (
	"fmt"
	"log"
	"strings"

	"github.com/go-resty/resty/v2"
)

// FetchAllCerts retrieves all required certificates from CDH/KBS
func FetchAllCerts(certURI, keyURI, clientCAURI string) ([]byte, []byte, []byte, error) {
	log.Println("Initializing certificate fetcher...")
	client := resty.New()

	// Fetch server certificate
	log.Printf("Fetching server certificate from URI: %s", certURI)
	cert, err := fetchResource(client, certURI)
	if err != nil {
		log.Printf("ERROR: Failed to fetch server certificate: %v", err)
		return nil, nil, nil, fmt.Errorf("failed to fetch server cert: %w", err)
	}
	log.Printf("Successfully fetched server certificate (%d bytes)", len(cert))

	// Fetch server key
	log.Printf("Fetching server key from URI: %s", keyURI)
	key, err := fetchResource(client, keyURI)
	if err != nil {
		log.Printf("ERROR: Failed to fetch server key: %v", err)
		return nil, nil, nil, fmt.Errorf("failed to fetch server key: %w", err)
	}
	log.Printf("Successfully fetched server key (%d bytes)", len(key))

	// Fetch client CA
	log.Printf("Fetching client CA certificate from URI: %s", clientCAURI)
	clientCA, err := fetchResource(client, clientCAURI)
	if err != nil {
		log.Printf("ERROR: Failed to fetch client CA: %v", err)
		return nil, nil, nil, fmt.Errorf("failed to fetch client CA: %w", err)
	}
	log.Printf("Successfully fetched client CA certificate (%d bytes)", len(clientCA))

	return cert, key, clientCA, nil
}

// fetchResource retrieves a resource from KBS via CDH
func fetchResource(client *resty.Client, kbsURI string) ([]byte, error) {
	// Convert KBS URI to CDH URL
	// kbs:///namespace/resource/key -> http://127.0.0.1:8006/cdh/resource/namespace/resource/key
	url := kbsURItoCDHURL(kbsURI)
	log.Printf("Converted KBS URI to CDH URL: %s", url)

	log.Printf("Sending GET request to CDH: %s", url)
	resp, err := client.R().Get(url)
	if err != nil {
		log.Printf("ERROR: CDH request failed for URL %s: %v", url, err)
		return nil, fmt.Errorf("CDH request failed: %w", err)
	}

	log.Printf("CDH response status: %d", resp.StatusCode())
	if resp.StatusCode() != 200 {
		log.Printf("ERROR: CDH returned non-200 status %d for URL %s: %s", resp.StatusCode(), url, resp.String())
		return nil, fmt.Errorf("CDH returned status %d: %s", resp.StatusCode(), resp.String())
	}

	log.Printf("Successfully retrieved resource from CDH (%d bytes)", len(resp.Body()))
	return resp.Body(), nil
}

// kbsURItoCDHURL converts KBS URI to CDH URL
func kbsURItoCDHURL(uri string) string {
	path := strings.TrimPrefix(uri, "kbs://")
	return "http://127.0.0.1:8006/cdh/resource" + path
}
