// Package status provides pod status collection and attestation status retrieval
package status

import (
	"encoding/json"
	"log"
	"os"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
)

const (
	// CDH endpoint for attestation status
	attestationStatusURL = "http://localhost:8006/cdh/resource/default/attestation-status/status"
)

// Status represents the current pod status
type Status struct {
	PodName   string `json:"podName"`
	Namespace string `json:"namespace"`
	Attested  bool   `json:"attested"`
}

// Attestation represents attestation details
type Attestation struct {
	Status    string `json:"status"`
	Timestamp string `json:"timestamp"`
	Details   string `json:"details"`
}

// Collector collects status information
type Collector struct {
	podName           string
	namespace         string
	attested          bool
	attestationStatus string
	attestationTime   time.Time
	attestationError  string
}

// NewCollector creates a new status collector
func NewCollector() *Collector {
	log.Println("Initializing status collector...")

	podName := getEnv("POD_NAME", "unknown")
	namespace := getEnv("POD_NAMESPACE", "default")

	log.Printf("Pod information: name=%s, namespace=%s", podName, namespace)

	c := &Collector{
		podName:   podName,
		namespace: namespace,
	}

	// Fetch attestation status on initialization
	log.Println("Fetching initial attestation status...")
	c.fetchAttestationStatus()

	log.Println("Status collector initialized successfully")
	return c
}

// fetchAttestationStatus retrieves attestation status from CDH
func (c *Collector) fetchAttestationStatus() {
	log.Printf("Fetching attestation status from CDH: %s", attestationStatusURL)
	client := resty.New()

	resp, err := client.R().Get(attestationStatusURL)
	if err != nil {
		log.Printf("ERROR: Failed to fetch attestation status from CDH: %v", err)
		c.attested = false
		c.attestationStatus = "unavailable"
		c.attestationError = err.Error()
		return
	}

	log.Printf("CDH attestation status response: HTTP %d", resp.StatusCode())
	if resp.StatusCode() != 200 {
		log.Printf("ERROR: CDH returned non-200 status %d for attestation: %s", resp.StatusCode(), resp.String())
		c.attested = false
		c.attestationStatus = "unavailable"
		c.attestationError = resp.String()
		return
	}

	// Check if response contains "success"
	statusValue := strings.TrimSpace(string(resp.Body()))
	c.attestationTime = time.Now()
	log.Printf("Attestation status value from CDH: '%s'", statusValue)

	if statusValue == "success" {
		c.attested = true
		c.attestationStatus = "verified"
		c.attestationError = ""
		log.Printf("✓ Attestation verified successfully at %s", c.attestationTime.Format(time.RFC3339))
	} else {
		c.attested = false
		c.attestationStatus = "failed"
		c.attestationError = "attestation status: " + statusValue
		log.Printf("✗ Attestation failed: status = %s", statusValue)
	}
}

// Collect gathers current status
func (c *Collector) Collect() *Status {
	log.Printf("Collecting status: pod=%s, namespace=%s, attested=%v", c.podName, c.namespace, c.attested)
	return &Status{
		PodName:   c.podName,
		Namespace: c.namespace,
		Attested:  c.attested,
	}
}

// GetAttestation returns attestation details
func (c *Collector) GetAttestation() *Attestation {
	details := "TEE attestation successful"
	if c.attestationError != "" {
		details = c.attestationError
	}

	timestamp := c.attestationTime.Format(time.RFC3339)
	if c.attestationTime.IsZero() {
		timestamp = "unavailable"
	}

	log.Printf("Returning attestation details: status=%s, timestamp=%s", c.attestationStatus, timestamp)
	return &Attestation{
		Status:    c.attestationStatus,
		Timestamp: timestamp,
		Details:   details,
	}
}

// ToJSON converts status to JSON
func (s *Status) ToJSON() []byte {
	data, _ := json.MarshalIndent(s, "", "  ")
	return data
}

// ToJSON converts attestation to JSON
func (a *Attestation) ToJSON() []byte {
	data, _ := json.MarshalIndent(a, "", "  ")
	return data
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
