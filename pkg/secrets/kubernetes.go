package secrets

import (
	"encoding/json"
	"fmt"
	"os/exec"
)

// SecretKeys holds the keys found in a K8s secret
type SecretKeys struct {
	Name      string
	Namespace string
	Keys      []string
}

// K8sSecret represents the structure of a K8s secret from kubectl output
type K8sSecret struct {
	Metadata struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	} `json:"metadata"`
	Data map[string]string `json:"data"` // Keys are base64 encoded values
}

// InspectSecret queries K8s to get all keys in a secret
// Returns error if kubectl fails or secret doesn't exist
func InspectSecret(secretName, namespace string) (*SecretKeys, error) {
	// Build kubectl command
	cmd := exec.Command("kubectl", "get", "secret", secretName, "-n", namespace, "-o", "json")

	// Execute command
	output, err := cmd.Output()
	if err != nil {
		// Check if it's an exit error with stderr
		if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("kubectl get secret failed: %s", string(exitErr.Stderr))
		}
		return nil, fmt.Errorf("kubectl get secret failed: %w", err)
	}

	// Parse JSON output
	var k8sSecret K8sSecret
	if err := json.Unmarshal(output, &k8sSecret); err != nil {
		return nil, fmt.Errorf("failed to parse kubectl output: %w", err)
	}

	// Extract keys
	keys := make([]string, 0, len(k8sSecret.Data))
	for key := range k8sSecret.Data {
		keys = append(keys, key)
	}

	return &SecretKeys{
		Name:      secretName,
		Namespace: namespace,
		Keys:      keys,
	}, nil
}

// InspectSecrets queries multiple secrets in batch
// Returns a map of secretName -> []keys
// Continues on errors and returns partial results
func InspectSecrets(refs []SecretReference) (map[string][]string, error) {
	result := make(map[string][]string)
	var lastError error

	for _, ref := range refs {
		// Skip if lookup not needed (all keys already known)
		if !ref.NeedsLookup {
			if len(ref.Keys) > 0 {
				result[ref.Name] = ref.Keys
			}
			continue
		}

		// Inspect the secret
		secretKeys, err := InspectSecret(ref.Name, ref.Namespace)
		if err != nil {
			// Store error but continue processing other secrets
			lastError = fmt.Errorf("failed to inspect secret %s/%s: %w", ref.Namespace, ref.Name, err)
			continue
		}

		// Merge with known keys
		allKeys := make(map[string]bool)
		for _, key := range ref.Keys {
			allKeys[key] = true
		}
		for _, key := range secretKeys.Keys {
			allKeys[key] = true
		}

		// Convert to slice
		keys := make([]string, 0, len(allKeys))
		for key := range allKeys {
			keys = append(keys, key)
		}

		result[ref.Name] = keys
	}

	return result, lastError
}
