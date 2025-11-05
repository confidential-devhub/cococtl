package secrets

import (
	"fmt"

	"github.com/confidential-devhub/cococtl/pkg/sealed"
)

// SealedSecretData holds the conversion result
type SealedSecretData struct {
	ResourceURI  string // kbs:///namespace/secret/key
	SealedSecret string // sealed.fakejwsheader.xxx.fakesignature
	SecretName   string // original K8s secret name
	Key          string // secret key name
	Namespace    string
}

// ConvertToSealed converts a secret reference to sealed secret format
func ConvertToSealed(namespace, secretName, key string) (*SealedSecretData, error) {
	// Build KBS resource URI
	// Format: kbs:///namespace/secretName/key
	resourceURI := fmt.Sprintf("kbs:///%s/%s/%s", namespace, secretName, key)

	// Generate sealed secret using existing sealed package
	sealedSecret, err := sealed.GenerateSealedSecret(resourceURI)
	if err != nil {
		return nil, fmt.Errorf("failed to generate sealed secret for %s: %w", resourceURI, err)
	}

	return &SealedSecretData{
		ResourceURI:  resourceURI,
		SealedSecret: sealedSecret,
		SecretName:   secretName,
		Key:          key,
		Namespace:    namespace,
	}, nil
}

// ConvertSecrets converts all secret references to sealed secrets
// Uses inspectedKeys to get all keys for secrets that need lookup
func ConvertSecrets(refs []SecretReference, inspectedKeys map[string][]string) ([]*SealedSecretData, error) {
	var result []*SealedSecretData

	for _, ref := range refs {
		// Determine which keys to convert
		var keysToConvert []string

		if inspectedKeys != nil {
			// Use inspected keys if available
			if keys, ok := inspectedKeys[ref.Name]; ok {
				keysToConvert = keys
			} else if len(ref.Keys) > 0 {
				// Fall back to known keys
				keysToConvert = ref.Keys
			} else {
				// No keys available - skip this secret
				return nil, fmt.Errorf("no keys found for secret %s/%s (inspection may have failed)", ref.Namespace, ref.Name)
			}
		} else {
			// No inspection data - use only known keys
			if len(ref.Keys) > 0 {
				keysToConvert = ref.Keys
			} else {
				return nil, fmt.Errorf("no keys specified for secret %s/%s (use --skip-secret-lookup=false to auto-detect)", ref.Namespace, ref.Name)
			}
		}

		// Convert each key to sealed secret
		for _, key := range keysToConvert {
			sealed, err := ConvertToSealed(ref.Namespace, ref.Name, key)
			if err != nil {
				return nil, err
			}
			result = append(result, sealed)
		}
	}

	return result, nil
}
