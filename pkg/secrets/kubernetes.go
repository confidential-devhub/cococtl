package secrets

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"gopkg.in/yaml.v3"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/confidential-devhub/cococtl/pkg/k8s"
)

// SecretKeys holds the keys found in a K8s secret
// Kept for backward compatibility with converter and cmd layer
type SecretKeys struct {
	Name      string
	Namespace string
	Keys      []string
}

// SecretToSecretKeys converts a corev1.Secret to SecretKeys format
func SecretToSecretKeys(secret *corev1.Secret) *SecretKeys {
	keys := make([]string, 0, len(secret.Data))
	for key := range secret.Data {
		keys = append(keys, key)
	}

	return &SecretKeys{
		Name:      secret.Name,
		Namespace: secret.Namespace,
		Keys:      keys,
	}
}

// ToSecretKeys converts a map of corev1.Secret to SecretKeys format
func ToSecretKeys(secrets map[string]*corev1.Secret) map[string]*SecretKeys {
	result := make(map[string]*SecretKeys, len(secrets))
	for name, secret := range secrets {
		result[name] = SecretToSecretKeys(secret)
	}
	return result
}

// InspectSecret queries K8s to get a secret using client-go
// If namespace is empty, uses current context namespace
// Returns typed *corev1.Secret with decoded Data field
func InspectSecret(ctx context.Context, clientset kubernetes.Interface, secretName, namespace string) (*corev1.Secret, error) {
	// Resolve empty namespace to current context namespace
	ns := namespace
	if ns == "" {
		var err error
		ns, err = k8s.GetCurrentNamespace()
		if err != nil {
			return nil, fmt.Errorf("failed to resolve namespace: %w", err)
		}
	}

	// Get secret using client-go
	secret, err := clientset.CoreV1().Secrets(ns).Get(ctx, secretName, metav1.GetOptions{})
	if err != nil {
		return nil, k8s.WrapError(err, "get", fmt.Sprintf("secret/%s", secretName), ns)
	}

	return secret, nil
}

// InspectSecrets queries multiple secrets in batch using client-go
// Returns a map of secretName -> *corev1.Secret
// Fails immediately on first error
func InspectSecrets(ctx context.Context, clientset kubernetes.Interface, refs []SecretReference) (map[string]*corev1.Secret, error) {
	result := make(map[string]*corev1.Secret)

	for _, ref := range refs {
		// Skip if lookup not needed (all keys already known)
		if !ref.NeedsLookup {
			if len(ref.Keys) > 0 {
				// For secrets that don't need lookup, create minimal corev1.Secret
				// with known keys populated
				data := make(map[string][]byte)
				for _, key := range ref.Keys {
					data[key] = []byte{} // Empty data - actual values unknown
				}

				// Resolve namespace if empty
				ns := ref.Namespace
				if ns == "" {
					var err error
					ns, err = k8s.GetCurrentNamespace()
					if err != nil {
						return nil, fmt.Errorf("failed to resolve namespace for secret %s: %w", ref.Name, err)
					}
				}

				result[ref.Name] = &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      ref.Name,
						Namespace: ns,
					},
					Data: data,
				}
			}
			continue
		}

		// clientset required for cluster lookup
		if clientset == nil {
			return nil, fmt.Errorf("cluster connection required to inspect secret %q (needs key enumeration for %s usage)", ref.Name, describeUsageTypes(ref.Usages))
		}

		// Inspect the secret using client-go
		secret, err := InspectSecret(ctx, clientset, ref.Name, ref.Namespace)
		if err != nil {
			// Fail immediately
			nsInfo := "current context namespace"
			if ref.Namespace != "" {
				nsInfo = "namespace " + ref.Namespace
			}
			return nil, fmt.Errorf("failed to inspect secret %s in %s: %w", ref.Name, nsInfo, err)
		}

		result[ref.Name] = secret
	}

	return result, nil
}

// GenerateSealedSecretYAML generates YAML for a K8s secret with sealed secret values
// Secret name will be original name with "-sealed" suffix
// Returns the sealed secret name and YAML content
func GenerateSealedSecretYAML(secretName, namespace string, sealedData map[string]string) (string, string, error) {
	sealedSecretName := secretName + "-sealed"

	// Build Kubernetes Secret structure using stringData for readability
	// stringData is functionally equivalent to data (Kubernetes auto-encodes on apply)
	secret := map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Secret",
		"metadata": map[string]interface{}{
			"name":      sealedSecretName,
			"namespace": namespace,
		},
		"type":       "Opaque",
		"stringData": sealedData,
	}

	// Omit namespace from metadata if empty (matches kubectl behavior)
	if namespace == "" {
		metadata := secret["metadata"].(map[string]interface{})
		delete(metadata, "namespace")
	}

	yamlData, err := yaml.Marshal(secret)
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal sealed secret YAML: %w", err)
	}

	return sealedSecretName, string(yamlData), nil
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
	yamlParts := make([]string, 0, len(secretMap))

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

// GetServiceAccountImagePullSecrets queries a service account for imagePullSecrets
// If namespace is empty, uses current context namespace
// Returns the first imagePullSecret name or empty string if none found
func GetServiceAccountImagePullSecrets(ctx context.Context, clientset kubernetes.Interface, serviceAccountName, namespace string) (string, error) {
	// Resolve empty namespace to current context namespace
	ns := namespace
	if ns == "" {
		var err error
		ns, err = k8s.GetCurrentNamespace()
		if err != nil {
			return "", fmt.Errorf("failed to resolve namespace: %w", err)
		}
	}

	// Get ServiceAccount using client-go
	sa, err := clientset.CoreV1().ServiceAccounts(ns).Get(ctx, serviceAccountName, metav1.GetOptions{})
	if err != nil {
		return "", k8s.WrapError(err, "get", fmt.Sprintf("serviceaccount/%s", serviceAccountName), ns)
	}

	// Typed field access - ImagePullSecrets is []corev1.LocalObjectReference
	if len(sa.ImagePullSecrets) == 0 {
		return "", nil
	}

	// Return first imagePullSecret name
	return sa.ImagePullSecrets[0].Name, nil
}

// describeUsageTypes returns a comma-separated list of usage types for error messages
func describeUsageTypes(usages []SecretUsage) string {
	types := make([]string, 0, len(usages))
	seen := make(map[string]bool)
	for _, u := range usages {
		if !seen[u.Type] {
			types = append(types, u.Type)
			seen[u.Type] = true
		}
	}
	return strings.Join(types, ", ")
}
