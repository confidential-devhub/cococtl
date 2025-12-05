// Package examples provides built-in example manifests for educational purposes.
package examples

import (
	_ "embed"
	"os"
)

// Example represents a built-in example manifest with metadata.
type Example struct {
	Name           string
	Description    string
	Manifest       string
	Scenario       string
	LearningPoints []string
}

//go:embed manifests/simple-pod.yaml
var simplePodYAML string

//go:embed manifests/deployment-secrets.yaml
var deploymentSecretsYAML string

//go:embed manifests/sidecar-service.yaml
var sidecarServiceYAML string

//go:embed example-config.toml
var exampleConfigTOML string

// Examples is the registry of all built-in examples.
var Examples = map[string]*Example{
	"simple-pod": {
		Name:        "Simple Pod",
		Description: "Basic pod transformation - your first CoCo deployment",
		Manifest:    simplePodYAML,
		Scenario:    "Developer deploying a simple web application with CoCo for the first time",
		LearningPoints: []string{
			"RuntimeClass configuration (kata-cc)",
			"InitData annotation generation (aa.toml, cdh.toml, policy.rego)",
			"Default restrictive policy enforcement",
			"No external dependencies required",
		},
	},
	"deployment-secrets": {
		Name:        "Deployment with Secrets",
		Description: "Secret conversion and sealing for confidential data",
		Manifest:    deploymentSecretsYAML,
		Scenario:    "Application using database credentials and API keys",
		LearningPoints: []string{
			"Secret detection (env variables, volumes, envFrom)",
			"Sealed secret format and structure",
			"KBS URI generation (kbs:///namespace/secret/key)",
			"Trustee KBS upload process",
			"Secret reference replacement in manifest",
		},
	},
	"sidecar-service": {
		Name:        "Sidecar with Service",
		Description: "Auto-detected sidecar port forwarding with mTLS",
		Manifest:    sidecarServiceYAML,
		Scenario:    "External HTTPS access to confidential application with mTLS termination",
		LearningPoints: []string{
			"Multi-document YAML support (Deployment + Service)",
			"Automatic port detection from Service targetPort",
			"Named port resolution (targetPort: http -> containerPort: 8080)",
			"Sidecar container injection for mTLS",
			"Certificate management (server cert, client CA)",
			"Service manifest generation",
		},
	},
}

// List returns all available example names.
func List() []string {
	names := make([]string, 0, len(Examples))
	for name := range Examples {
		names = append(names, name)
	}
	return names
}

// Get returns an example by name, or nil if not found.
func Get(name string) *Example {
	return Examples[name]
}

// GetExampleConfigPath writes the example config to a temp file and returns its path.
// The caller is responsible for cleaning up the temp file when done.
func GetExampleConfigPath() (string, error) {
	tmpFile, err := os.CreateTemp("", "coco-example-config-*.toml")
	if err != nil {
		return "", err
	}
	defer func() {
		_ = tmpFile.Close() // Best effort cleanup
	}()

	if _, err := tmpFile.WriteString(exampleConfigTOML); err != nil {
		_ = os.Remove(tmpFile.Name()) // Best effort cleanup
		return "", err
	}

	return tmpFile.Name(), nil
}
