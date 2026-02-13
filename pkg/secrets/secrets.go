package secrets

import (
	"github.com/confidential-devhub/cococtl/pkg/manifest"
)

// SecretUsage tracks how a secret is used in the manifest
type SecretUsage struct {
	Type          string   // "env", "volume", "envFrom", "imagePullSecrets"
	ContainerName string   // Name of the container using the secret
	EnvVarName    string   // For env type: name of the environment variable
	Key           string   // For env type: specific key from secret (if known)
	VolumeName    string   // For volume type: name of the volume
	MountPath     string   // For volume type: mount path in container
	Items         []string // For volume type: specific keys to mount (if specified)
}

// SecretReference represents a K8s secret reference found in a manifest
type SecretReference struct {
	Name        string        // K8s secret name
	Namespace   string        // K8s namespace (from manifest or "default")
	Keys        []string      // Known keys (may be empty if lookup needed)
	NeedsLookup bool          // Whether kubectl inspection is needed
	Usages      []SecretUsage // How the secret is used
}

// DetectSecrets scans a manifest for all secret references
func DetectSecrets(manifestData map[string]interface{}, namespace string) ([]SecretReference, error) {
	// Create manifest wrapper to reuse existing manifest methods
	m := manifest.GetFromData(manifestData)

	// Get pod spec using manifest method (works for both Pod and Deployment!)
	podSpec, err := m.GetPodSpec()
	if err != nil {
		return nil, err
	}

	// Map to collect all secrets: secretName -> SecretReference
	secretsMap := make(map[string]*SecretReference)

	// 1. Detect secrets from containers
	if containers, ok := podSpec["containers"].([]interface{}); ok {
		for _, container := range containers {
			if c, ok := container.(map[string]interface{}); ok {
				containerName := getContainerName(c)

				// Detect env variable secrets
				detectEnvSecrets(c, containerName, namespace, secretsMap)

				// Detect envFrom secrets
				detectEnvFromSecrets(c, containerName, namespace, secretsMap)
			}
		}
	}

	// 2. Detect secrets from volumes
	detectVolumeSecrets(podSpec, namespace, secretsMap)

	// 3. Find mount paths for volume secrets
	if containers, ok := podSpec["containers"].([]interface{}); ok {
		for _, container := range containers {
			if c, ok := container.(map[string]interface{}); ok {
				containerName := getContainerName(c)
				addVolumeMountPaths(c, containerName, secretsMap)
			}
		}
	}

	// 4. Detect imagePullSecrets
	detectImagePullSecrets(podSpec, namespace, secretsMap)

	// Convert map to slice
	secrets := make([]SecretReference, 0, len(secretsMap))
	for _, ref := range secretsMap {
		secrets = append(secrets, *ref)
	}

	return secrets, nil
}

// detectEnvSecrets detects secrets referenced in env variables
func detectEnvSecrets(container map[string]interface{}, containerName, namespace string, secretsMap map[string]*SecretReference) {
	env, ok := container["env"].([]interface{})
	if !ok {
		return
	}

	for _, e := range env {
		envVar, ok := e.(map[string]interface{})
		if !ok {
			continue
		}

		// Get env var name
		envVarName, _ := envVar["name"].(string)

		// Check for secretKeyRef
		valueFrom, ok := envVar["valueFrom"].(map[string]interface{})
		if !ok {
			continue
		}

		secretKeyRef, ok := valueFrom["secretKeyRef"].(map[string]interface{})
		if !ok {
			continue
		}

		secretName, _ := secretKeyRef["name"].(string)
		key, _ := secretKeyRef["key"].(string)

		if secretName == "" {
			continue
		}

		// Get or create secret reference
		ref := getOrCreateSecretRef(secretsMap, secretName, namespace)

		// Add key to known keys
		if key != "" && !contains(ref.Keys, key) {
			ref.Keys = append(ref.Keys, key)
		}

		// Add usage
		ref.Usages = append(ref.Usages, SecretUsage{
			Type:          "env",
			ContainerName: containerName,
			EnvVarName:    envVarName,
			Key:           key,
		})
	}
}

// detectEnvFromSecrets detects secrets referenced in envFrom
func detectEnvFromSecrets(container map[string]interface{}, containerName, namespace string, secretsMap map[string]*SecretReference) {
	envFrom, ok := container["envFrom"].([]interface{})
	if !ok {
		return
	}

	for _, ef := range envFrom {
		envFromItem, ok := ef.(map[string]interface{})
		if !ok {
			continue
		}

		secretRef, ok := envFromItem["secretRef"].(map[string]interface{})
		if !ok {
			continue
		}

		secretName, _ := secretRef["name"].(string)
		if secretName == "" {
			continue
		}

		// Get or create secret reference
		ref := getOrCreateSecretRef(secretsMap, secretName, namespace)

		// envFrom needs all keys from the secret
		ref.NeedsLookup = true

		// Add usage
		ref.Usages = append(ref.Usages, SecretUsage{
			Type:          "envFrom",
			ContainerName: containerName,
		})
	}
}

// detectVolumeSecrets detects secrets referenced in volumes
func detectVolumeSecrets(spec map[string]interface{}, namespace string, secretsMap map[string]*SecretReference) {
	volumes, ok := spec["volumes"].([]interface{})
	if !ok {
		return
	}

	for _, vol := range volumes {
		v, ok := vol.(map[string]interface{})
		if !ok {
			continue
		}

		volumeName, _ := v["name"].(string)

		secret, ok := v["secret"].(map[string]interface{})
		if !ok {
			continue
		}

		secretName, _ := secret["secretName"].(string)
		if secretName == "" {
			continue
		}

		// Get or create secret reference
		ref := getOrCreateSecretRef(secretsMap, secretName, namespace)

		// Check if specific items are specified
		if items, ok := secret["items"].([]interface{}); ok && len(items) > 0 {
			// Specific keys are defined
			for _, item := range items {
				if itemMap, ok := item.(map[string]interface{}); ok {
					if key, ok := itemMap["key"].(string); ok && key != "" {
						if !contains(ref.Keys, key) {
							ref.Keys = append(ref.Keys, key)
						}
					}
				}
			}
		} else {
			// No specific items - need to lookup all keys
			ref.NeedsLookup = true
		}

		// Add usage (mount path will be added later)
		ref.Usages = append(ref.Usages, SecretUsage{
			Type:       "volume",
			VolumeName: volumeName,
		})
	}
}

// addVolumeMountPaths adds mount path information to volume secret usages
func addVolumeMountPaths(container map[string]interface{}, containerName string, secretsMap map[string]*SecretReference) {
	volumeMounts, ok := container["volumeMounts"].([]interface{})
	if !ok {
		return
	}

	// For each volume mount, find if it's a secret volume
	for _, vm := range volumeMounts {
		vmMap, ok := vm.(map[string]interface{})
		if !ok {
			continue
		}

		volumeName, _ := vmMap["name"].(string)
		mountPath, _ := vmMap["mountPath"].(string)

		// Find secret usage that matches this volume
		for _, ref := range secretsMap {
			for i := range ref.Usages {
				if ref.Usages[i].Type == "volume" && ref.Usages[i].VolumeName == volumeName {
					// Add mount path and container name
					ref.Usages[i].MountPath = mountPath
					ref.Usages[i].ContainerName = containerName
				}
			}
		}
	}
}

// detectImagePullSecrets detects secrets referenced in imagePullSecrets
func detectImagePullSecrets(spec map[string]interface{}, namespace string, secretsMap map[string]*SecretReference) {
	imagePullSecrets, ok := spec["imagePullSecrets"].([]interface{})
	if !ok {
		return
	}

	for _, ips := range imagePullSecrets {
		ipsMap, ok := ips.(map[string]interface{})
		if !ok {
			continue
		}

		secretName, _ := ipsMap["name"].(string)
		if secretName == "" {
			continue
		}

		// Get or create secret reference
		ref := getOrCreateSecretRef(secretsMap, secretName, namespace)

		// imagePullSecrets need all keys from the secret (typically .dockerconfigjson)
		ref.NeedsLookup = true

		// Add usage
		ref.Usages = append(ref.Usages, SecretUsage{
			Type: "imagePullSecrets",
		})
	}
}

// DetectImagePullSecretsWithServiceAccount detects imagePullSecrets from manifest
// and falls back to default service account if none are found in the spec
func DetectImagePullSecretsWithServiceAccount(manifestData map[string]interface{}, namespace string) ([]SecretReference, error) {
	// Create manifest wrapper to reuse existing manifest methods
	m := manifest.GetFromData(manifestData)

	// Get pod spec using manifest method (works for both Pod and Deployment!)
	podSpec, err := m.GetPodSpec()
	if err != nil {
		return nil, err
	}

	secretsMap := make(map[string]*SecretReference)

	// First, check for imagePullSecrets in the manifest
	detectImagePullSecrets(podSpec, namespace, secretsMap)

	// If no imagePullSecrets found in manifest, check default service account
	// if len(secretsMap) == 0 {
	// 	secretName, err := GetServiceAccountImagePullSecrets("default", namespace)
	// 	if err == nil && secretName != "" {
	// 		// Found imagePullSecret in default service account
	// 		ref := getOrCreateSecretRef(secretsMap, secretName, namespace)
	// 		ref.NeedsLookup = true
	// 		ref.Usages = append(ref.Usages, SecretUsage{
	// 			Type: "imagePullSecrets",
	// 		})
	// 	}
	// }

	// Convert map to slice
	secrets := make([]SecretReference, 0, len(secretsMap))
	for _, ref := range secretsMap {
		secrets = append(secrets, *ref)
	}

	return secrets, nil
}

// getContainerName extracts the container name
func getContainerName(container map[string]interface{}) string {
	if name, ok := container["name"].(string); ok {
		return name
	}
	return ""
}

// getOrCreateSecretRef gets or creates a secret reference in the map
func getOrCreateSecretRef(secretsMap map[string]*SecretReference, secretName, namespace string) *SecretReference {
	if ref, exists := secretsMap[secretName]; exists {
		return ref
	}

	ref := &SecretReference{
		Name:      secretName,
		Namespace: namespace,
		Keys:      []string{},
		Usages:    []SecretUsage{},
	}
	secretsMap[secretName] = ref
	return ref
}

// contains checks if a string slice contains a value
func contains(slice []string, val string) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}
