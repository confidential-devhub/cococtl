// Package manifest handles Kubernetes manifest manipulation and transformation.
package manifest

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Manifest represents a Kubernetes manifest.
type Manifest struct {
	data map[string]interface{}
	path string
}

// Set represents a collection of Kubernetes manifests from a multi-document YAML file.
type Set struct {
	manifests []*Manifest
	path      string
}

// Load reads and parses a Kubernetes manifest from a file.
func Load(path string) (*Manifest, error) {
	// Validate and sanitize the path to prevent directory traversal
	// Source - https://stackoverflow.com/a/57534618
	// Posted by Kenny Grant, modified by community. See post 'Timeline' for change history
	// Retrieved 2025-11-14, License - CC BY-SA 4.0
	cleanPath := filepath.Clean(path)

	// For absolute paths, validate they don't escape the filesystem root
	// For relative paths, ensure they're relative to current directory
	if filepath.IsAbs(cleanPath) {
		// Absolute paths are allowed for manifest files
		// but ensure path doesn't contain traversal attempts
		if strings.Contains(path, "..") {
			return nil, fmt.Errorf("invalid manifest path: contains directory traversal")
		}
	} else {
		// For relative paths, ensure they resolve within current directory
		cwd, err := os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("failed to get current directory: %w", err)
		}
		absPath := filepath.Join(cwd, cleanPath)
		if !strings.HasPrefix(absPath, cwd) {
			return nil, fmt.Errorf("invalid manifest path: escapes current directory")
		}
		cleanPath = absPath
	}

	// #nosec G304 - Path is validated above
	data, err := os.ReadFile(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read manifest file: %w", err)
	}

	var manifestData map[string]interface{}
	if err := yaml.Unmarshal(data, &manifestData); err != nil {
		return nil, fmt.Errorf("failed to parse YAML manifest: %w", err)
	}

	return &Manifest{
		data: manifestData,
		path: cleanPath,
	}, nil
}

// LoadMultiDocument reads and parses a multi-document Kubernetes manifest file.
// It handles YAML files with multiple documents separated by '---'.
// Returns a Set containing all documents. If only one document is found,
// it still returns a Set with a single Manifest for consistency.
func LoadMultiDocument(path string) (*Set, error) {
	// Validate and sanitize the path to prevent directory traversal
	// Source - https://stackoverflow.com/a/57534618
	// Posted by Kenny Grant, modified by community. See post 'Timeline' for change history
	// Retrieved 2025-11-14, License - CC BY-SA 4.0
	cleanPath := filepath.Clean(path)

	// For absolute paths, validate they don't escape the filesystem root
	// For relative paths, ensure they're relative to current directory
	if filepath.IsAbs(cleanPath) {
		// Absolute paths are allowed for manifest files
		// but ensure path doesn't contain traversal attempts
		if strings.Contains(path, "..") {
			return nil, fmt.Errorf("invalid manifest path: contains directory traversal")
		}
	} else {
		// For relative paths, ensure they resolve within current directory
		cwd, err := os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("failed to get current directory: %w", err)
		}
		absPath := filepath.Join(cwd, cleanPath)
		if !strings.HasPrefix(absPath, cwd) {
			return nil, fmt.Errorf("invalid manifest path: escapes current directory")
		}
		cleanPath = absPath
	}

	// #nosec G304 - Path is validated above
	data, err := os.ReadFile(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read manifest file: %w", err)
	}

	// Split by YAML document separator
	documents := strings.Split(string(data), "\n---")
	if len(documents) == 0 {
		return nil, fmt.Errorf("no documents found in manifest file")
	}

	manifests := make([]*Manifest, 0, len(documents))
	for i, doc := range documents {
		// Skip empty documents
		trimmed := strings.TrimSpace(doc)
		if trimmed == "" || trimmed == "---" {
			continue
		}

		var manifestData map[string]interface{}
		if err := yaml.Unmarshal([]byte(doc), &manifestData); err != nil {
			return nil, fmt.Errorf("failed to parse YAML document %d: %w", i+1, err)
		}

		// Skip empty manifests (e.g., only comments)
		if len(manifestData) == 0 {
			continue
		}

		manifests = append(manifests, &Manifest{
			data: manifestData,
			path: cleanPath,
		})
	}

	if len(manifests) == 0 {
		return nil, fmt.Errorf("no valid documents found in manifest file")
	}

	return &Set{
		manifests: manifests,
		path:      cleanPath,
	}, nil
}

// GetFromData creates a Manifest from raw manifest data.
// This is useful for packages that need to use Manifest methods on raw data without loading from a file.
func GetFromData(data map[string]interface{}) *Manifest {
	return &Manifest{
		data: data,
		path: "", // No path when created from raw data
	}
}

// GetManifests returns all manifests in the set.
func (ms *Set) GetManifests() []*Manifest {
	return ms.manifests
}

// GetPrimaryManifest returns the first workload manifest (Pod, Deployment, etc.).
// Returns nil if no workload manifest is found.
func (ms *Set) GetPrimaryManifest() *Manifest {
	workloadKinds := map[string]bool{
		"Pod": true, "Deployment": true, "StatefulSet": true,
		"DaemonSet": true, "ReplicaSet": true, "Job": true,
	}

	for _, m := range ms.manifests {
		if workloadKinds[m.GetKind()] {
			return m
		}
	}
	return nil
}

// GetServiceManifest returns the first Service manifest.
// Returns nil if no Service is found.
func (ms *Set) GetServiceManifest() *Manifest {
	for _, m := range ms.manifests {
		if m.GetKind() == "Service" {
			return m
		}
	}
	return nil
}

// GetServiceTargetPort extracts the targetPort from a Service manifest.
// It looks for the first port in spec.ports[].
// If targetPort is a named port, it resolves it by looking at the primary workload's container ports.
// Returns 0 if no port is found.
// Returns error if the manifest is not a Service or has invalid structure.
func (ms *Set) GetServiceTargetPort() (int, error) {
	svc := ms.GetServiceManifest()
	if svc == nil {
		return 0, nil // No service found, not an error
	}

	primary := ms.GetPrimaryManifest()
	return extractTargetPort(svc, primary)
}

// extractTargetPort extracts targetPort from a Service manifest.
// If targetPort is a named port and workload is provided, it resolves the name
// by looking at the workload's container ports.
func extractTargetPort(svc *Manifest, workload *Manifest) (int, error) {
	if svc.GetKind() != "Service" {
		return 0, fmt.Errorf("manifest is not a Service, got %s", svc.GetKind())
	}

	spec, err := svc.GetSpec()
	if err != nil {
		return 0, fmt.Errorf("failed to get Service spec: %w", err)
	}

	ports, ok := spec["ports"].([]interface{})
	if !ok || len(ports) == 0 {
		return 0, fmt.Errorf("no ports found in Service spec")
	}

	// Get the first port
	firstPort, ok := ports[0].(map[string]interface{})
	if !ok {
		return 0, fmt.Errorf("invalid port structure in Service spec")
	}

	// targetPort can be a number or a string (named port)
	targetPort, ok := firstPort["targetPort"]
	if !ok {
		// If targetPort is not specified, it defaults to the value of port
		if port, ok := firstPort["port"].(int); ok {
			return port, nil
		}
		if port, ok := firstPort["port"].(float64); ok {
			return int(port), nil
		}
		return 0, fmt.Errorf("no targetPort found in Service port spec")
	}

	// Handle both int and float64 (YAML unmarshals numbers as float64)
	switch v := targetPort.(type) {
	case int:
		return v, nil
	case float64:
		return int(v), nil
	case string:
		// Named port - try to resolve it from the workload manifest
		if workload == nil {
			return 0, fmt.Errorf("targetPort is a named port (%s), but no workload manifest available for resolution", v)
		}
		resolvedPort, err := resolveNamedPort(workload, v)
		if err != nil {
			return 0, fmt.Errorf("failed to resolve named port %s: %w", v, err)
		}
		return resolvedPort, nil
	default:
		return 0, fmt.Errorf("targetPort has unexpected type: %T", v)
	}
}

// resolveNamedPort resolves a named port by looking at the workload's container ports.
// It searches all containers in the pod spec for a port with the given name.
func resolveNamedPort(m *Manifest, portName string) (int, error) {
	podSpec, err := m.GetPodSpec()
	if err != nil {
		return 0, fmt.Errorf("failed to get pod spec: %w", err)
	}

	containers, ok := podSpec["containers"].([]interface{})
	if !ok || len(containers) == 0 {
		return 0, fmt.Errorf("no containers found in pod spec")
	}

	// Search all containers for the named port
	for _, container := range containers {
		c, ok := container.(map[string]interface{})
		if !ok {
			continue
		}

		ports, ok := c["ports"].([]interface{})
		if !ok {
			continue
		}

		for _, port := range ports {
			p, ok := port.(map[string]interface{})
			if !ok {
				continue
			}

			// Check if this port has the name we're looking for
			name, hasName := p["name"].(string)
			if !hasName || name != portName {
				continue
			}

			// Found the named port, extract containerPort
			if containerPort, ok := p["containerPort"].(int); ok {
				return containerPort, nil
			}
			if containerPort, ok := p["containerPort"].(float64); ok {
				return int(containerPort), nil
			}
		}
	}

	return 0, fmt.Errorf("named port %s not found in any container", portName)
}

// Save writes the manifest to a file.
func (m *Manifest) Save(path string) error {
	data, err := yaml.Marshal(m.data)
	if err != nil {
		return fmt.Errorf("failed to marshal manifest: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
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

// GetNamespace returns the namespace of the resource
func (m *Manifest) GetNamespace() string {
	if metadata, ok := m.data["metadata"].(map[string]interface{}); ok {
		if namespace, ok := metadata["namespace"].(string); ok {
			return namespace
		}
	}
	return ""
}

// SetRuntimeClass sets or updates the runtimeClassName in the pod spec
func (m *Manifest) SetRuntimeClass(runtimeClass string) error {
	podSpec, err := m.GetPodSpec()
	if err != nil {
		return err
	}

	podSpec["runtimeClassName"] = runtimeClass
	return nil
}

// GetRuntimeClass returns the current runtimeClassName
func (m *Manifest) GetRuntimeClass() string {
	podSpec, err := m.GetPodSpec()
	if err != nil {
		return ""
	}

	if rc, ok := podSpec["runtimeClassName"].(string); ok {
		return rc
	}
	return ""
}

// SetAnnotation sets an annotation on the resource
// For workload resources (Deployment, StatefulSet, etc.), sets annotation on pod template
// For Pod resources, sets annotation on the pod metadata
func (m *Manifest) SetAnnotation(key, value string) error {
	kind := m.GetKind()

	// For workload resources, set annotation on pod template
	if kind == "Deployment" || kind == "StatefulSet" || kind == "DaemonSet" || kind == "ReplicaSet" || kind == "Job" {
		return m.setPodTemplateAnnotation(key, value)
	}

	// For Pod and other resources, set on resource metadata
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

// setPodTemplateAnnotation sets an annotation on the pod template metadata
func (m *Manifest) setPodTemplateAnnotation(key, value string) error {
	spec, err := m.GetSpec()
	if err != nil {
		return err
	}

	template, ok := spec["template"].(map[string]interface{})
	if !ok {
		template = make(map[string]interface{})
		spec["template"] = template
	}

	metadata, ok := template["metadata"].(map[string]interface{})
	if !ok {
		metadata = make(map[string]interface{})
		template["metadata"] = metadata
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
// For workload resources, gets annotation from pod template
// For Pod resources, gets annotation from pod metadata
func (m *Manifest) GetAnnotation(key string) string {
	kind := m.GetKind()

	// For workload resources, get annotation from pod template
	if kind == "Deployment" || kind == "StatefulSet" || kind == "DaemonSet" || kind == "ReplicaSet" || kind == "Job" {
		return m.getPodTemplateAnnotation(key)
	}

	// For Pod and other resources, get from resource metadata
	if metadata, ok := m.data["metadata"].(map[string]interface{}); ok {
		if annotations, ok := metadata["annotations"].(map[string]interface{}); ok {
			if value, ok := annotations[key].(string); ok {
				return value
			}
		}
	}
	return ""
}

// getPodTemplateAnnotation retrieves an annotation from the pod template metadata
func (m *Manifest) getPodTemplateAnnotation(key string) string {
	spec, err := m.GetSpec()
	if err != nil {
		return ""
	}

	template, ok := spec["template"].(map[string]interface{})
	if !ok {
		return ""
	}

	metadata, ok := template["metadata"].(map[string]interface{})
	if !ok {
		return ""
	}

	annotations, ok := metadata["annotations"].(map[string]interface{})
	if !ok {
		return ""
	}

	if value, ok := annotations[key].(string); ok {
		return value
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

// GetPodSpec returns the pod spec, whether it's a direct Pod or a Deployment/StatefulSet/DaemonSet
func (m *Manifest) GetPodSpec() (map[string]interface{}, error) {
	kind := m.GetKind()
	spec, err := m.GetSpec()
	if err != nil {
		return nil, err
	}

	// For Deployment, StatefulSet, DaemonSet, ReplicaSet, Job
	if kind == "Deployment" || kind == "StatefulSet" || kind == "DaemonSet" || kind == "ReplicaSet" || kind == "Job" {
		template, ok := spec["template"].(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("template field not found in %s spec", kind)
		}
		podSpec, ok := template["spec"].(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("spec field not found in template")
		}
		return podSpec, nil
	}

	// For Pod, return the spec directly
	return spec, nil
}

// GetPodLabels returns labels from the pod template (for Deployments/etc) or pod metadata (for Pods)
func (m *Manifest) GetPodLabels() (map[string]interface{}, error) {
	kind := m.GetKind()

	// For workload resources, get labels from pod template
	if kind == "Deployment" || kind == "StatefulSet" || kind == "DaemonSet" || kind == "ReplicaSet" || kind == "Job" {
		spec, err := m.GetSpec()
		if err != nil {
			return nil, err
		}

		template, ok := spec["template"].(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("template field not found in %s spec", kind)
		}

		metadata, ok := template["metadata"].(map[string]interface{})
		if !ok {
			return make(map[string]interface{}), nil
		}

		labels, ok := metadata["labels"].(map[string]interface{})
		if !ok {
			return make(map[string]interface{}), nil
		}

		return labels, nil
	}

	// For Pod, get labels from resource metadata
	if metadata, ok := m.data["metadata"].(map[string]interface{}); ok {
		if labels, ok := metadata["labels"].(map[string]interface{}); ok {
			return labels, nil
		}
	}

	return make(map[string]interface{}), nil
}

// GetSecretRefs returns all secret references in the manifest (names only).
// This is a simplified helper for displaying secret names.
// For full secret metadata (usage types, keys, namespace), use secrets.DetectSecrets() instead.
func (m *Manifest) GetSecretRefs() []string {
	secrets := make(map[string]bool)

	// Use GetPodSpec to handle both Pod and Deployment/StatefulSet/etc
	podSpec, err := m.GetPodSpec()
	if err != nil {
		return []string{}
	}

	// Check containers
	if containers, ok := podSpec["containers"].([]interface{}); ok {
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
	if volumes, ok := podSpec["volumes"].([]interface{}); ok {
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
	// Use GetPodSpec to handle both Pod and Deployment/StatefulSet/etc
	podSpec, err := m.GetPodSpec()
	if err != nil {
		return err
	}

	// Replace in containers
	if containers, ok := podSpec["containers"].([]interface{}); ok {
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

				// Replace in envFrom
				if envFrom, ok := c["envFrom"].([]interface{}); ok {
					for _, ef := range envFrom {
						if envFromItem, ok := ef.(map[string]interface{}); ok {
							if secretRef, ok := envFromItem["secretRef"].(map[string]interface{}); ok {
								if name, ok := secretRef["name"].(string); ok && name == oldName {
									secretRef["name"] = newName
								}
							}
						}
					}
				}
			}
		}
	}

	// Replace in volumes
	if volumes, ok := podSpec["volumes"].([]interface{}); ok {
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
	podSpec, err := m.GetPodSpec()
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
	if existing, ok := podSpec["initContainers"].([]interface{}); ok {
		// Prepend new initContainer to existing list
		initContainers = append([]interface{}{initContainer}, existing...)
	} else {
		// Create new list with just this initContainer
		initContainers = []interface{}{initContainer}
	}

	podSpec["initContainers"] = initContainers
	return nil
}

// GetInitContainers returns the list of initContainers
func (m *Manifest) GetInitContainers() []interface{} {
	podSpec, err := m.GetPodSpec()
	if err != nil {
		return []interface{}{}
	}

	if initContainers, ok := podSpec["initContainers"].([]interface{}); ok {
		return initContainers
	}

	return []interface{}{}
}

// AddVolume adds a volume to the spec
func (m *Manifest) AddVolume(name, volumeType string, config map[string]interface{}) error {
	podSpec, err := m.GetPodSpec()
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
	if existing, ok := podSpec["volumes"].([]interface{}); ok {
		volumes = existing
	} else {
		volumes = []interface{}{}
	}

	// Append new volume
	volumes = append(volumes, volume)
	podSpec["volumes"] = volumes

	return nil
}

// AddVolumeMountToContainer adds a volumeMount to a specific container
func (m *Manifest) AddVolumeMountToContainer(containerName, volumeName, mountPath string) error {
	podSpec, err := m.GetPodSpec()
	if err != nil {
		return err
	}

	containers, ok := podSpec["containers"].([]interface{})
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

// ConvertEnvSecretToSealed replaces secretKeyRef with sealed secret value
func (m *Manifest) ConvertEnvSecretToSealed(containerName, envVarName, sealedSecret string) error {
	podSpec, err := m.GetPodSpec()
	if err != nil {
		return err
	}

	containers, ok := podSpec["containers"].([]interface{})
	if !ok {
		return fmt.Errorf("no containers found in spec")
	}

	// Find the container and env variable
	for _, container := range containers {
		c, ok := container.(map[string]interface{})
		if !ok {
			continue
		}

		// Check if this is the target container
		name, _ := c["name"].(string)
		if containerName != "" && name != containerName {
			continue
		}

		// Find the env variable
		env, ok := c["env"].([]interface{})
		if !ok {
			continue
		}

		for _, e := range env {
			envVar, ok := e.(map[string]interface{})
			if !ok {
				continue
			}

			envName, _ := envVar["name"].(string)
			if envName != envVarName {
				continue
			}

			// Replace secretKeyRef with value
			delete(envVar, "valueFrom")
			envVar["value"] = sealedSecret
			return nil
		}
	}

	return fmt.Errorf("env variable %s not found in container %s", envVarName, containerName)
}

// ConvertVolumeSecretToInitContainer replaces secret volume with initContainer download
func (m *Manifest) ConvertVolumeSecretToInitContainer(
	secretName string,
	sealedSecrets map[string]string, // key -> sealed secret
	volumeName string,
	mountPath string,
	initContainerImage string,
) error {
	podSpec, err := m.GetPodSpec()
	if err != nil {
		return err
	}

	// 1. Remove the secret volume and replace with emptyDir
	if err := m.RemoveSecretVolume(volumeName); err != nil {
		return err
	}

	emptyDirConfig := map[string]interface{}{
		"medium": "Memory",
	}
	if err := m.AddVolume(volumeName, "emptyDir", emptyDirConfig); err != nil {
		return err
	}

	// 2. Create initContainer to download each secret key
	downloadCommands := make([]string, 0, len(sealedSecrets))
	for key := range sealedSecrets {
		// Build CDH URL from resource URI
		namespace := m.GetNamespace()
		if namespace == "" {
			namespace = "default"
		}
		resourceURI := fmt.Sprintf("kbs:///%s/%s/%s", namespace, secretName, key)
		cdhURL := strings.Replace(resourceURI, "kbs://", "http://127.0.0.1:8006/cdh/resource", 1)

		// Build file path
		filePath := fmt.Sprintf("%s/%s", strings.TrimSuffix(mountPath, "/"), key)

		// Add download command
		downloadCommands = append(downloadCommands, fmt.Sprintf("curl -o %s %s", filePath, cdhURL))
	}

	// Combine all commands
	fullCommand := strings.Join(downloadCommands, " && ")

	// Create initContainer
	initContainer := map[string]interface{}{
		"name":    "get-secrets-" + secretName,
		"image":   initContainerImage,
		"command": []interface{}{"sh", "-c", fullCommand},
		"volumeMounts": []interface{}{
			map[string]interface{}{
				"name":      volumeName,
				"mountPath": mountPath,
			},
		},
	}

	// Add initContainer
	var initContainers []interface{}
	if existing, ok := podSpec["initContainers"].([]interface{}); ok {
		initContainers = append(existing, initContainer)
	} else {
		initContainers = []interface{}{initContainer}
	}
	podSpec["initContainers"] = initContainers

	return nil
}

// RemoveSecretVolume removes a secret-type volume from the spec
func (m *Manifest) RemoveSecretVolume(volumeName string) error {
	podSpec, err := m.GetPodSpec()
	if err != nil {
		return err
	}

	volumes, ok := podSpec["volumes"].([]interface{})
	if !ok {
		return nil // No volumes to remove
	}

	// Find and remove the volume
	newVolumes := make([]interface{}, 0, len(volumes))
	for _, vol := range volumes {
		v, ok := vol.(map[string]interface{})
		if !ok {
			newVolumes = append(newVolumes, vol)
			continue
		}

		name, _ := v["name"].(string)
		if name == volumeName {
			// Skip this volume (remove it)
			continue
		}

		newVolumes = append(newVolumes, vol)
	}

	podSpec["volumes"] = newVolumes
	return nil
}

// GetImagePullSecrets returns all imagePullSecrets in the manifest
func (m *Manifest) GetImagePullSecrets() []string {
	secrets := make([]string, 0)

	podSpec, err := m.GetPodSpec()
	if err != nil {
		return secrets
	}

	imagePullSecrets, ok := podSpec["imagePullSecrets"].([]interface{})
	if !ok {
		return secrets
	}

	for _, ips := range imagePullSecrets {
		if ipsMap, ok := ips.(map[string]interface{}); ok {
			if name, ok := ipsMap["name"].(string); ok && name != "" {
				secrets = append(secrets, name)
			}
		}
	}

	return secrets
}

// RemoveImagePullSecrets removes all imagePullSecrets from the manifest
// These will be handled via initdata instead
func (m *Manifest) RemoveImagePullSecrets() error {
	podSpec, err := m.GetPodSpec()
	if err != nil {
		return err
	}

	// Remove imagePullSecrets field
	delete(podSpec, "imagePullSecrets")
	return nil
}

// AddSidecarContainer adds a sidecar container to the pod spec
func (m *Manifest) AddSidecarContainer(container map[string]interface{}) error {
	podSpec, err := m.GetPodSpec()
	if err != nil {
		return err
	}

	// Get existing containers
	containers, ok := podSpec["containers"].([]interface{})
	if !ok {
		containers = []interface{}{}
	}

	// Append sidecar container
	containers = append(containers, container)
	podSpec["containers"] = containers

	return nil
}

// ConvertEnvFromSecret converts envFrom secretRef to individual env vars with sealed secrets
func (m *Manifest) ConvertEnvFromSecret(containerName, secretName string, sealedSecretsMap map[string]string) error {
	podSpec, err := m.GetPodSpec()
	if err != nil {
		return err
	}

	containers, ok := podSpec["containers"].([]interface{})
	if !ok {
		return fmt.Errorf("no containers found in spec")
	}

	// Find the container
	for _, container := range containers {
		c, ok := container.(map[string]interface{})
		if !ok {
			continue
		}

		// Check if this is the target container
		name, _ := c["name"].(string)
		if containerName != "" && name != containerName {
			continue
		}

		// Remove envFrom entry for this secret
		envFrom, ok := c["envFrom"].([]interface{})
		if ok {
			var newEnvFrom []interface{}
			for _, ef := range envFrom {
				efMap, ok := ef.(map[string]interface{})
				if !ok {
					newEnvFrom = append(newEnvFrom, ef)
					continue
				}

				secretRef, ok := efMap["secretRef"].(map[string]interface{})
				if !ok {
					newEnvFrom = append(newEnvFrom, ef)
					continue
				}

				refName, _ := secretRef["name"].(string)
				if refName != secretName {
					newEnvFrom = append(newEnvFrom, ef)
				}
				// Skip this secretRef (we're converting it to env vars)
			}

			if len(newEnvFrom) > 0 {
				c["envFrom"] = newEnvFrom
			} else {
				delete(c, "envFrom")
			}
		}

		// Add individual env variables
		var env []interface{}
		if existing, ok := c["env"].([]interface{}); ok {
			env = existing
		} else {
			env = []interface{}{}
		}

		// Add each sealed secret as an env var
		for key, sealedSecret := range sealedSecretsMap {
			envVar := map[string]interface{}{
				"name":  key,
				"value": sealedSecret,
			}
			env = append(env, envVar)
		}

		c["env"] = env
		return nil
	}

	return fmt.Errorf("container %s not found", containerName)
}
