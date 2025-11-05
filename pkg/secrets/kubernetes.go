package secrets

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
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
// If namespace is empty, uses current context namespace (no -n flag)
// Returns error if kubectl fails or secret doesn't exist
func InspectSecret(secretName, namespace string) (*SecretKeys, error) {
	// Build kubectl command
	var cmd *exec.Cmd
	if namespace != "" {
		// Explicit namespace specified
		cmd = exec.Command("kubectl", "get", "secret", secretName, "-n", namespace, "-o", "json")
	} else {
		// No namespace specified - use current context namespace
		cmd = exec.Command("kubectl", "get", "secret", secretName, "-o", "json")
	}

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

	// Use the actual namespace from kubectl response (not the input parameter)
	actualNamespace := k8sSecret.Metadata.Namespace

	return &SecretKeys{
		Name:      secretName,
		Namespace: actualNamespace,
		Keys:      keys,
	}, nil
}

// InspectSecrets queries multiple secrets in batch
// Returns a map of secretName -> SecretKeys (includes namespace and keys)
// Fails immediately on first error
func InspectSecrets(refs []SecretReference) (map[string]*SecretKeys, error) {
	result := make(map[string]*SecretKeys)

	for _, ref := range refs {
		// Skip if lookup not needed (all keys already known)
		if !ref.NeedsLookup {
			if len(ref.Keys) > 0 {
				// For secrets that don't need lookup, we still need namespace
				// Use the namespace from ref (could be empty or explicit)
				// If empty, it will be resolved during conversion
				result[ref.Name] = &SecretKeys{
					Name:      ref.Name,
					Namespace: ref.Namespace,
					Keys:      ref.Keys,
				}
			}
			continue
		}

		// Inspect the secret
		secretKeys, err := InspectSecret(ref.Name, ref.Namespace)
		if err != nil {
			// Fail immediately
			nsInfo := "current context namespace"
			if ref.Namespace != "" {
				nsInfo = "namespace " + ref.Namespace
			}
			return nil, fmt.Errorf("failed to inspect secret %s in %s: %w", ref.Name, nsInfo, err)
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

		// Store with actual namespace from kubectl
		result[ref.Name] = &SecretKeys{
			Name:      ref.Name,
			Namespace: secretKeys.Namespace,
			Keys:      keys,
		}
	}

	return result, nil
}

// GenerateSealedSecretYAML generates YAML for a K8s secret with sealed secret values
// Secret name will be original name with "-sealed" suffix
// Returns the sealed secret name and YAML content
func GenerateSealedSecretYAML(secretName, namespace string, sealedData map[string]string) (string, string, error) {
	sealedSecretName := secretName + "-sealed"

	// Build kubectl command to create secret
	args := []string{"create", "secret", "generic", sealedSecretName}

	// Add namespace if specified
	if namespace != "" {
		args = append(args, "-n", namespace)
	}

	// Add each sealed secret as a literal
	for key, sealedValue := range sealedData {
		args = append(args, fmt.Sprintf("--from-literal=%s=%s", key, sealedValue))
	}

	// Add --dry-run=client and -o yaml to generate YAML without applying
	args = append(args, "--dry-run=client", "-o", "yaml")

	// Execute command to generate YAML
	cmd := exec.Command("kubectl", args...)
	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return "", "", fmt.Errorf("kubectl create secret failed: %s", string(exitErr.Stderr))
		}
		return "", "", fmt.Errorf("kubectl create secret failed: %w", err)
	}

	return sealedSecretName, string(output), nil
}

// CreateSealedSecret creates a K8s secret with sealed secret values
// Secret name will be original name with "-sealed" suffix
// Returns the name of the created secret
func CreateSealedSecret(secretName, namespace string, sealedData map[string]string) (string, error) {
	sealedSecretName, yamlContent, err := GenerateSealedSecretYAML(secretName, namespace, sealedData)
	if err != nil {
		return "", err
	}

	// Now apply the secret
	applyCmd := exec.Command("kubectl", "apply", "-f", "-")
	if namespace != "" {
		applyCmd = exec.Command("kubectl", "apply", "-f", "-", "-n", namespace)
	}
	applyCmd.Stdin = strings.NewReader(yamlContent)

	if output, err := applyCmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("kubectl apply secret failed: %s", string(output))
	}

	return sealedSecretName, nil
}

// GenerateSealedSecretsYAML generates YAML manifests for sealed secrets
// Returns a map of original secret name -> sealed secret name, and a combined YAML string
func GenerateSealedSecretsYAML(sealedSecrets []*SealedSecretData) (map[string]string, string, error) {
	// Group by secret name
	secretMap := make(map[string]map[string]string) // secretName -> key -> sealedValue

	for _, sealed := range sealedSecrets {
		if secretMap[sealed.SecretName] == nil {
			secretMap[sealed.SecretName] = make(map[string]string)
		}
		secretMap[sealed.SecretName][sealed.Key] = sealed.SealedSecret
	}

	// Generate YAML for each sealed secret
	result := make(map[string]string)
	var yamlParts []string

	for secretName, sealedData := range secretMap {
		// Use namespace from first sealed secret entry
		var namespace string
		for _, sealed := range sealedSecrets {
			if sealed.SecretName == secretName {
				namespace = sealed.Namespace
				break
			}
		}

		sealedSecretName, yamlContent, err := GenerateSealedSecretYAML(secretName, namespace, sealedData)
		if err != nil {
			return nil, "", fmt.Errorf("failed to generate sealed secret YAML for %s: %w", secretName, err)
		}

		result[secretName] = sealedSecretName
		yamlParts = append(yamlParts, yamlContent)
	}

	// Combine all YAMLs with --- separator
	combinedYAML := strings.Join(yamlParts, "---\n")

	return result, combinedYAML, nil
}

// CreateSealedSecrets creates K8s sealed secrets for all provided sealed secret data
// Returns a map of original secret name -> sealed secret name
func CreateSealedSecrets(sealedSecrets []*SealedSecretData) (map[string]string, error) {
	// Group by secret name
	secretMap := make(map[string]map[string]string) // secretName -> key -> sealedValue

	for _, sealed := range sealedSecrets {
		if secretMap[sealed.SecretName] == nil {
			secretMap[sealed.SecretName] = make(map[string]string)
		}
		secretMap[sealed.SecretName][sealed.Key] = sealed.SealedSecret
	}

	// Create sealed secrets
	result := make(map[string]string)

	for secretName, sealedData := range secretMap {
		// Use namespace from first sealed secret entry
		var namespace string
		for _, sealed := range sealedSecrets {
			if sealed.SecretName == secretName {
				namespace = sealed.Namespace
				break
			}
		}

		sealedSecretName, err := CreateSealedSecret(secretName, namespace, sealedData)
		if err != nil {
			return nil, fmt.Errorf("failed to create sealed secret for %s: %w", secretName, err)
		}

		result[secretName] = sealedSecretName
	}

	return result, nil
}
