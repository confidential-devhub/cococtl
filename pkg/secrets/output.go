package secrets

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// TrusteeSecretEntry represents one secret in Trustee config
type TrusteeSecretEntry struct {
	ResourceURI  string                 `yaml:"resourceUri"`
	SealedSecret string                 `yaml:"sealedSecret"`
	JSON         map[string]interface{} `yaml:"json"` // The unsealed JSON spec
}

// TrusteeConfig is the output configuration file
type TrusteeConfig struct {
	Secrets []TrusteeSecretEntry `yaml:"secrets"`
}

// GenerateTrusteeConfig creates the Trustee configuration file
func GenerateTrusteeConfig(sealedSecrets []*SealedSecretData, outputPath string) error {
	config := TrusteeConfig{
		Secrets: make([]TrusteeSecretEntry, 0, len(sealedSecrets)),
	}

	for _, sealed := range sealedSecrets {
		// Decode the sealed secret to extract the JSON spec
		jsonSpec, err := decodeSealedSecret(sealed.SealedSecret)
		if err != nil {
			return fmt.Errorf("failed to decode sealed secret for %s: %w", sealed.ResourceURI, err)
		}

		entry := TrusteeSecretEntry{
			ResourceURI:  sealed.ResourceURI,
			SealedSecret: sealed.SealedSecret,
			JSON:         jsonSpec,
		}
		config.Secrets = append(config.Secrets, entry)
	}

	// Marshal to YAML
	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal Trustee config: %w", err)
	}

	// Write to file
	if err := os.WriteFile(outputPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write Trustee config file: %w", err)
	}

	return nil
}

// PrintTrusteeInstructions prints console instructions for setting up Trustee
// autoUploadSuccess indicates whether secrets were automatically uploaded to Trustee
func PrintTrusteeInstructions(sealedSecrets []*SealedSecretData, configPath string, autoUploadSuccess bool) {
	if len(sealedSecrets) == 0 {
		return
	}

	fmt.Println()
	fmt.Println("Trustee KBS Configuration")
	fmt.Println("═════════════════════════════════════════════════════════")

	if autoUploadSuccess {
		fmt.Printf("✓ Successfully added %d secret(s) to Trustee KBS\n\n", len(sealedSecrets))
		fmt.Println("The following sealed secrets are configured:")
	} else {
		fmt.Printf("The following %d sealed secret(s) need to be added to your Trustee KBS:\n\n", len(sealedSecrets))
	}

	fmt.Println()

	for i, sealed := range sealedSecrets {
		fmt.Printf("%d. %s\n", i+1, sealed.ResourceURI)

		// Wrap long sealed secrets for readability
		sealedStr := sealed.SealedSecret
		if len(sealedStr) > 80 {
			fmt.Printf("   Sealed: %s\n", sealedStr[:80])
			for j := 80; j < len(sealedStr); j += 80 {
				end := j + 80
				if end > len(sealedStr) {
					end = len(sealedStr)
				}
				fmt.Printf("           %s\n", sealedStr[j:end])
			}
		} else {
			fmt.Printf("   Sealed: %s\n", sealedStr)
		}
		fmt.Println()
	}

	fmt.Printf("Full configuration saved to: %s\n", configPath)
	fmt.Println()

	if autoUploadSuccess {
		fmt.Println("Note: Secrets have been automatically uploaded to Trustee KBS.")
		fmt.Println("      The configuration file above is saved for your reference.")
	} else {
		// fmt.Println("Note: Automatic Trustee upload failed or was skipped.")
		fmt.Println("Please manually configure these secrets in your Trustee KBS")
		fmt.Println("using the configuration file above.")
	}
	fmt.Println()
}

// decodeSealedSecret decodes a sealed secret to extract the JSON payload
// Format: sealed.fakejwsheader.<base64url_json>.fakesignature
func decodeSealedSecret(sealedSecret string) (map[string]interface{}, error) {
	// Split by dots
	parts := strings.Split(sealedSecret, ".")
	if len(parts) != 4 {
		return nil, fmt.Errorf("invalid sealed secret format")
	}

	// The JSON payload is in the third part (index 2)
	encodedJSON := parts[2]

	// Decode base64url
	jsonBytes, err := base64.RawURLEncoding.DecodeString(encodedJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64url: %w", err)
	}

	// Parse JSON
	var jsonSpec map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &jsonSpec); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	return jsonSpec, nil
}
