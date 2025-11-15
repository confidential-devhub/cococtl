// Package secrets provides secret conversion and management for sealed secrets.
package secrets

import (
	"fmt"
	"strings"

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
	// Strip leading "." from key name as KBS doesn't support it in URIs
	// e.g., ".dockerconfigjson" becomes "dockerconfigjson"
	cleanKey := strings.TrimPrefix(key, ".")

	// Build KBS resource URI
	// Format: kbs:///namespace/secretName/key
	resourceURI := fmt.Sprintf("kbs:///%s/%s/%s", namespace, secretName, cleanKey)

	// Generate sealed secret using existing sealed package
	sealedSecret, err := sealed.GenerateSealedSecret(resourceURI)
	if err != nil {
		return nil, fmt.Errorf("failed to generate sealed secret for %s: %w", resourceURI, err)
	}

	return &SealedSecretData{
		ResourceURI:  resourceURI,
		SealedSecret: sealedSecret,
		SecretName:   secretName,
		Key:          cleanKey,
		Namespace:    namespace,
	}, nil
}

// ConvertSecrets converts all secret references to sealed secrets
// Uses inspectedKeys to get all keys for secrets that need lookup
func ConvertSecrets(refs []SecretReference, inspectedKeys map[string]*SecretKeys) ([]*SealedSecretData, error) {
	var result []*SealedSecretData

	for _, ref := range refs {
		// Determine which keys to convert and actual namespace
		var keysToConvert []string
		var namespace string

		if inspectedKeys != nil {
			// Use inspected keys if available
			if secretKeys, ok := inspectedKeys[ref.Name]; ok {
				keysToConvert = secretKeys.Keys
				namespace = secretKeys.Namespace
			} else if len(ref.Keys) > 0 {
				// Fall back to known keys
				keysToConvert = ref.Keys
				namespace = ref.Namespace
			} else {
				// No keys available
				nsInfo := "current context namespace"
				if ref.Namespace != "" {
					nsInfo = "namespace " + ref.Namespace
				}
				return nil, fmt.Errorf("no keys found for secret %s in %s (inspection may have failed)", ref.Name, nsInfo)
			}
		} else {
			// No inspection data - use only known keys
			if len(ref.Keys) > 0 {
				keysToConvert = ref.Keys
				namespace = ref.Namespace
			} else {
				nsInfo := "current context namespace"
				if ref.Namespace != "" {
					nsInfo = "namespace " + ref.Namespace
				}
				return nil, fmt.Errorf("no keys found for secret %s in %s (kubectl inspection failed and no explicit keys in manifest)", ref.Name, nsInfo)
			}
		}

		// Convert each key to sealed secret
		for _, key := range keysToConvert {
			sealed, err := ConvertToSealed(namespace, ref.Name, key)
			if err != nil {
				return nil, err
			}
			result = append(result, sealed)
		}
	}

	return result, nil
}
