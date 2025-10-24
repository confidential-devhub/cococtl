package manifest

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Manifest represents a Kubernetes manifest
type Manifest struct {
	data map[string]interface{}
	path string
}

// Load reads and parses a Kubernetes manifest from a file
func Load(path string) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read manifest file: %w", err)
	}

	var manifestData map[string]interface{}
	if err := yaml.Unmarshal(data, &manifestData); err != nil {
		return nil, fmt.Errorf("failed to parse YAML manifest: %w", err)
	}

	return &Manifest{
		data: manifestData,
		path: path,
	}, nil
}

// Save writes the manifest to a file
func (m *Manifest) Save(path string) error {
	data, err := yaml.Marshal(m.data)
	if err != nil {
		return fmt.Errorf("failed to marshal manifest: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write manifest file: %w", err)
	}

	return nil
}

// Backup creates a backup of the manifest with -coco suffix
func (m *Manifest) Backup() (string, error) {
	if m.path == "" {
		return "", fmt.Errorf("original path not set")
	}

	ext := filepath.Ext(m.path)
	baseName := strings.TrimSuffix(m.path, ext)
	backupPath := fmt.Sprintf("%s-coco%s", baseName, ext)

	if err := m.Save(backupPath); err != nil {
		return "", fmt.Errorf("failed to create backup: %w", err)
	}

	return backupPath, nil
}

// GetKind returns the kind of the Kubernetes resource
func (m *Manifest) GetKind() string {
	if kind, ok := m.data["kind"].(string); ok {
		return kind
	}
	return ""
}

// GetName returns the name of the resource
func (m *Manifest) GetName() string {
	if metadata, ok := m.data["metadata"].(map[string]interface{}); ok {
		if name, ok := metadata["name"].(string); ok {
			return name
		}
	}
	return ""
}

// SetRuntimeClass sets or updates the runtimeClassName in the spec
func (m *Manifest) SetRuntimeClass(runtimeClass string) error {
	spec, ok := m.data["spec"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("spec field not found or invalid")
	}

	spec["runtimeClassName"] = runtimeClass
	return nil
}

// GetRuntimeClass returns the current runtimeClassName
func (m *Manifest) GetRuntimeClass() string {
	if spec, ok := m.data["spec"].(map[string]interface{}); ok {
		if rc, ok := spec["runtimeClassName"].(string); ok {
			return rc
		}
	}
	return ""
}

// SetAnnotation sets an annotation on the resource
func (m *Manifest) SetAnnotation(key, value string) error {
	metadata, ok := m.data["metadata"].(map[string]interface{})
	if !ok {
		metadata = make(map[string]interface{})
		m.data["metadata"] = metadata
	}

	annotations, ok := metadata["annotations"].(map[string]interface{})
	if !ok {
		annotations = make(map[string]interface{})
		metadata["annotations"] = annotations
	}

	annotations[key] = value
	return nil
}

// GetAnnotation retrieves an annotation value
func (m *Manifest) GetAnnotation(key string) string {
	if metadata, ok := m.data["metadata"].(map[string]interface{}); ok {
		if annotations, ok := metadata["annotations"].(map[string]interface{}); ok {
			if value, ok := annotations[key].(string); ok {
				return value
			}
		}
	}
	return ""
}

// GetData returns the raw manifest data
func (m *Manifest) GetData() map[string]interface{} {
	return m.data
}

// GetSpec returns the spec section of the manifest
func (m *Manifest) GetSpec() (map[string]interface{}, error) {
	spec, ok := m.data["spec"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("spec field not found or invalid")
	}
	return spec, nil
}
