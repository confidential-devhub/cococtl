package sealed

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// SecretSpec represents the sealed secret specification
type SecretSpec struct {
	Version          string                 `json:"version"`
	Type             string                 `json:"type"`
	Name             string                 `json:"name"`
	Provider         string                 `json:"provider"`
	ProviderSettings map[string]interface{} `json:"provider_settings"`
	Annotations      map[string]interface{} `json:"annotations"`
}

// GenerateSealedSecret creates a sealed secret from a KBS resource URI
// Format: sealed.fakejwsheader.{base64url_encoded_json}.fakesignature
func GenerateSealedSecret(resourceURI string) (string, error) {
	// Create the secret specification
	spec := SecretSpec{
		Version:          "0.1.0",
		Type:             "vault",
		Name:             resourceURI,
		Provider:         "kbs",
		ProviderSettings: make(map[string]interface{}),
		Annotations:      make(map[string]interface{}),
	}

	// Marshal to JSON
	jsonData, err := json.Marshal(spec)
	if err != nil {
		return "", fmt.Errorf("failed to marshal secret spec: %w", err)
	}

	// Encode to base64url (unpadded)
	encoded := base64.RawURLEncoding.EncodeToString(jsonData)

	// Create sealed secret format
	sealedSecret := fmt.Sprintf("sealed.fakejwsheader.%s.fakesignature", encoded)

	return sealedSecret, nil
}

// ParseResourceURI extracts the path components from a KBS resource URI
// Example: kbs:///default/mysecret/user -> namespace=default, resource=mysecret, key=user
func ParseResourceURI(uri string) (namespace, resource, key string, err error) {
	// Remove kbs:// prefix
	if !strings.HasPrefix(uri, "kbs://") {
		return "", "", "", fmt.Errorf("invalid KBS URI format, must start with kbs://")
	}

	// Remove prefix and split by /
	path := strings.TrimPrefix(uri, "kbs://")
	parts := strings.Split(strings.Trim(path, "/"), "/")

	if len(parts) < 3 {
		return "", "", "", fmt.Errorf("invalid KBS URI format, expected kbs:///namespace/resource/key")
	}

	return parts[0], parts[1], parts[2], nil
}
