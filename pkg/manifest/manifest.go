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

// GetSecretRefs returns all secret references in the manifest
func (m *Manifest) GetSecretRefs() []string {
	secrets := make(map[string]bool)

	spec, err := m.GetSpec()
	if err != nil {
		return []string{}
	}

	// Check containers
	if containers, ok := spec["containers"].([]interface{}); ok {
		for _, container := range containers {
			if c, ok := container.(map[string]interface{}); ok {
				// Check env variables
				if env, ok := c["env"].([]interface{}); ok {
					for _, e := range env {
						if envVar, ok := e.(map[string]interface{}); ok {
							if valueFrom, ok := envVar["valueFrom"].(map[string]interface{}); ok {
								if secretKeyRef, ok := valueFrom["secretKeyRef"].(map[string]interface{}); ok {
									if name, ok := secretKeyRef["name"].(string); ok {
										secrets[name] = true
									}
								}
							}
						}
					}
				}

				// Check volume mounts - we need to look at volumes
			}
		}
	}

	// Check volumes
	if volumes, ok := spec["volumes"].([]interface{}); ok {
		for _, vol := range volumes {
			if v, ok := vol.(map[string]interface{}); ok {
				if secret, ok := v["secret"].(map[string]interface{}); ok {
					if secretName, ok := secret["secretName"].(string); ok {
						secrets[secretName] = true
					}
				}
			}
		}
	}

	// Convert map to slice
	result := make([]string, 0, len(secrets))
	for s := range secrets {
		result = append(result, s)
	}

	return result
}

// ReplaceSecretName replaces all occurrences of oldName with newName in secret references
func (m *Manifest) ReplaceSecretName(oldName, newName string) error {
	spec, err := m.GetSpec()
	if err != nil {
		return err
	}

	// Replace in containers
	if containers, ok := spec["containers"].([]interface{}); ok {
		for _, container := range containers {
			if c, ok := container.(map[string]interface{}); ok {
				// Replace in env variables
				if env, ok := c["env"].([]interface{}); ok {
					for _, e := range env {
						if envVar, ok := e.(map[string]interface{}); ok {
							if valueFrom, ok := envVar["valueFrom"].(map[string]interface{}); ok {
								if secretKeyRef, ok := valueFrom["secretKeyRef"].(map[string]interface{}); ok {
									if name, ok := secretKeyRef["name"].(string); ok && name == oldName {
										secretKeyRef["name"] = newName
									}
								}
							}
						}
					}
				}
			}
		}
	}

	// Replace in volumes
	if volumes, ok := spec["volumes"].([]interface{}); ok {
		for _, vol := range volumes {
			if v, ok := vol.(map[string]interface{}); ok {
				if secret, ok := v["secret"].(map[string]interface{}); ok {
					if secretName, ok := secret["secretName"].(string); ok && secretName == oldName {
						secret["secretName"] = newName
					}
				}
			}
		}
	}

	return nil
}

// AddInitContainer adds an initContainer to the beginning of the initContainers list
func (m *Manifest) AddInitContainer(name, image string, command []string) error {
	spec, err := m.GetSpec()
	if err != nil {
		return err
	}

	// Create the initContainer
	initContainer := map[string]interface{}{
		"name":  name,
		"image": image,
	}

	if len(command) > 0 {
		initContainer["command"] = command
	}

	// Get existing initContainers or create new list
	var initContainers []interface{}
	if existing, ok := spec["initContainers"].([]interface{}); ok {
		// Prepend new initContainer to existing list
		initContainers = append([]interface{}{initContainer}, existing...)
	} else {
		// Create new list with just this initContainer
		initContainers = []interface{}{initContainer}
	}

	spec["initContainers"] = initContainers
	return nil
}

// GetInitContainers returns the list of initContainers
func (m *Manifest) GetInitContainers() []interface{} {
	spec, err := m.GetSpec()
	if err != nil {
		return []interface{}{}
	}

	if initContainers, ok := spec["initContainers"].([]interface{}); ok {
		return initContainers
	}

	return []interface{}{}
}

// AddVolume adds a volume to the spec
func (m *Manifest) AddVolume(name, volumeType string, config map[string]interface{}) error {
	spec, err := m.GetSpec()
	if err != nil {
		return err
	}

	// Create volume definition
	volume := map[string]interface{}{
		"name": name,
	}

	// Add volume-specific configuration
	volume[volumeType] = config

	// Get existing volumes or create new list
	var volumes []interface{}
	if existing, ok := spec["volumes"].([]interface{}); ok {
		volumes = existing
	} else {
		volumes = []interface{}{}
	}

	// Append new volume
	volumes = append(volumes, volume)
	spec["volumes"] = volumes

	return nil
}

// AddVolumeMountToContainer adds a volumeMount to a specific container
func (m *Manifest) AddVolumeMountToContainer(containerName, volumeName, mountPath string) error {
	spec, err := m.GetSpec()
	if err != nil {
		return err
	}

	containers, ok := spec["containers"].([]interface{})
	if !ok {
		return fmt.Errorf("no containers found in spec")
	}

	// Find the container and add volumeMount
	for _, container := range containers {
		c, ok := container.(map[string]interface{})
		if !ok {
			continue
		}

		// Check if this is the target container (or add to all if containerName is empty)
		if containerName != "" {
			if name, ok := c["name"].(string); !ok || name != containerName {
				continue
			}
		}

		// Get existing volumeMounts or create new list
		var volumeMounts []interface{}
		if existing, ok := c["volumeMounts"].([]interface{}); ok {
			volumeMounts = existing
		} else {
			volumeMounts = []interface{}{}
		}

		// Add new volumeMount
		volumeMount := map[string]interface{}{
			"name":      volumeName,
			"mountPath": mountPath,
		}
		volumeMounts = append(volumeMounts, volumeMount)
		c["volumeMounts"] = volumeMounts

		// If specific container name was provided, we're done
		if containerName != "" {
			return nil
		}
	}

	return nil
}
