// Package explain provides analysis and explanation of CoCo transformations.
package explain

import (
	"fmt"

	"github.com/confidential-devhub/cococtl/pkg/config"
	"github.com/confidential-devhub/cococtl/pkg/manifest"
	"github.com/confidential-devhub/cococtl/pkg/secrets"
)

// Transformation represents a single transformation that would be applied.
type Transformation struct {
	Type        string   // "runtime", "secret", "initdata", "sidecar", "annotation"
	Name        string   // Human-readable name
	Description string   // What this transformation does
	Reason      string   // Why this transformation is needed
	Before      string   // Before state (YAML snippet or description)
	After       string   // After state (YAML snippet or description)
	Details     []string // Additional details/notes
}

// Analysis represents the complete analysis of a manifest.
type Analysis struct {
	ManifestPath    string
	ResourceKind    string
	ResourceName    string
	HasService      bool
	ServicePort     int
	Transformations []Transformation
	SecretCount     int
	SidecarEnabled  bool
}

// Analyze performs a complete analysis of what transformations would be applied.
func Analyze(manifestPath string, cfg *config.CocoConfig, enableSidecar bool, sidecarPortForward int) (*Analysis, error) {
	// Load manifest
	manifestSet, err := manifest.LoadMultiDocument(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load manifest: %w", err)
	}

	primary := manifestSet.GetPrimaryManifest()
	if primary == nil {
		return nil, fmt.Errorf("no workload manifest (Pod, Deployment, etc.) found in file")
	}

	analysis := &Analysis{
		ManifestPath:    manifestPath,
		ResourceKind:    primary.GetKind(),
		ResourceName:    primary.GetName(),
		Transformations: []Transformation{},
	}

	// Check for Service
	svc := manifestSet.GetServiceManifest()
	if svc != nil {
		analysis.HasService = true
		port, _ := manifestSet.GetServiceTargetPort()
		analysis.ServicePort = port
	}

	// 1. RuntimeClass transformation
	analysis.Transformations = append(analysis.Transformations, analyzeRuntimeClass(primary, cfg))

	// 2. Secret transformations
	secretTransformations, secretCount := analyzeSecrets(primary)
	analysis.SecretCount = secretCount
	analysis.Transformations = append(analysis.Transformations, secretTransformations...)

	// 3. Sidecar transformation
	if enableSidecar {
		analysis.SidecarEnabled = true
		sidecarTransform := analyzeSidecar(cfg, analysis.ServicePort, sidecarPortForward)
		if sidecarTransform != nil {
			analysis.Transformations = append(analysis.Transformations, *sidecarTransform)
		}
	}

	// 4. InitData transformation
	analysis.Transformations = append(analysis.Transformations, analyzeInitData(cfg, analysis.SecretCount))

	// 5. Custom annotations
	if len(cfg.Annotations) > 0 {
		analysis.Transformations = append(analysis.Transformations, analyzeAnnotations(cfg))
	}

	return analysis, nil
}

func analyzeRuntimeClass(m *manifest.Manifest, cfg *config.CocoConfig) Transformation {
	existingRC := m.GetRuntimeClass()
	targetRC := cfg.RuntimeClass

	before := "spec:\n  containers: [...]"
	if existingRC != "" {
		before = fmt.Sprintf("spec:\n  runtimeClassName: %s\n  containers: [...]", existingRC)
	}

	after := fmt.Sprintf("spec:\n  runtimeClassName: %s  ← %s\n  containers: [...]",
		targetRC,
		getChangeMarker(existingRC, targetRC))

	description := "Configure Kata Containers runtime for confidential execution"
	if existingRC != "" && existingRC != targetRC {
		description = fmt.Sprintf("Update runtime from %s to %s", existingRC, targetRC)
	}

	return Transformation{
		Type:        "runtime",
		Name:        "RuntimeClass Configuration",
		Description: description,
		Reason:      "Sets Kata Containers runtime class to provide TEE (Trusted Execution Environment) isolation using confidential VMs",
		Before:      before,
		After:       after,
		Details: []string{
			"RuntimeClass must be already configured in the cluster",
			"Provides hardware-based isolation",
			"Runs workload in encrypted memory",
		},
	}
}

func analyzeSecrets(m *manifest.Manifest) ([]Transformation, int) {
	// Detect secrets
	allSecretRefs, err := secrets.DetectSecrets(m.GetData(), m.GetNamespace())
	if err != nil || len(allSecretRefs) == 0 {
		return nil, 0
	}

	// Filter out imagePullSecrets
	var secretRefs []secrets.SecretReference
	for _, ref := range allSecretRefs {
		isImagePullSecret := false
		for _, usage := range ref.Usages {
			if usage.Type == "imagePullSecrets" {
				isImagePullSecret = true
				break
			}
		}
		if !isImagePullSecret {
			secretRefs = append(secretRefs, ref)
		}
	}

	if len(secretRefs) == 0 {
		return nil, 0
	}

	transformations := make([]Transformation, 0, len(secretRefs))

	for _, ref := range secretRefs {
		for _, usage := range ref.Usages {
			var before, after string

			switch usage.Type {
			case "env":
				before = fmt.Sprintf("env:\n  - name: %s\n    valueFrom:\n      secretKeyRef:\n        name: %s\n        key: %s",
					usage.EnvVarName, ref.Name, usage.Key)
				after = fmt.Sprintf("env:\n  - name: %s\n    value: \"sealed.fake.eyJrYnNfd...\"  ← SEALED",
					usage.EnvVarName)

			case "envFrom":
				before = fmt.Sprintf("envFrom:\n  - secretRef:\n      name: %s", ref.Name)
				after = "env:  ← EXPANDED\n  - name: KEY1\n    value: \"sealed.fake.eyJrYnNfd...\"\n  - name: KEY2\n    value: \"sealed.fake.eyJrYnNfd...\""

			case "volume":
				before = fmt.Sprintf("volumes:\n  - name: %s\n    secret:\n      secretName: %s", usage.VolumeName, ref.Name)
				after = fmt.Sprintf("volumes:\n  - name: %s\n    emptyDir:\n      medium: Memory  ← CHANGED\ninitContainers:  ← ADDED\n  - name: get-secrets-%s\n    image: fedora:44\n    command: [\"curl\", \"-o\", \"...\", \"http://localhost:8006/cdh/resource/...\"]",
					usage.VolumeName, ref.Name)
			}

			transformations = append(transformations, Transformation{
				Type:        "secret",
				Name:        fmt.Sprintf("Secret Conversion: %s", ref.Name),
				Description: fmt.Sprintf("Convert %s secret to sealed format", usage.Type),
				Reason:      "Secrets must be sealed and retrieved from Trustee KBS to maintain confidentiality",
				Before:      before,
				After:       after,
				Details: []string{
					fmt.Sprintf("Original secret uploaded to Trustee at: kbs:///%s/%s/*", ref.Namespace, ref.Name),
					"Sealed format: sealed.fake.{base64url_json}.fake",
					"Guest retrieves via CDH (Confidential Data Hub)",
					"Only accessible inside TEE after attestation",
				},
			})
		}
	}

	return transformations, len(secretRefs)
}

func analyzeSidecar(cfg *config.CocoConfig, servicePort, manualPort int) *Transformation {
	port := manualPort
	portSource := "manual (--sidecar-port-forward)"

	if port == 0 && servicePort > 0 {
		port = servicePort
		portSource = "auto-detected from Service"
	}

	if port == 0 {
		return nil
	}

	return &Transformation{
		Type:        "sidecar",
		Name:        "Sidecar Container Injection",
		Description: fmt.Sprintf("Add mTLS termination sidecar (forwarding port %d)", port),
		Reason:      "Provides secure external HTTPS access with mutual TLS authentication",
		Before:      "spec:\n  containers:\n    - name: app\n      image: myapp:latest",
		After: fmt.Sprintf("spec:\n  containers:\n    - name: app\n      image: myapp:latest\n    - name: coco-secure-access  ← ADDED\n      image: %s\n      env:\n        - FORWARD_PORT: \"%d\"\n        - HTTPS_PORT: \"8443\"",
			cfg.Sidecar.Image, port),
		Details: []string{
			fmt.Sprintf("Port %d detected: %s", port, portSource),
			"Exposes HTTPS on port 8443 (external access)",
			"Forwards to app on port " + fmt.Sprintf("%d", port) + " (internal)",
			"Requires client certificate for mTLS authentication",
			"Server certificate retrieved from Trustee KBS",
		},
	}
}

func analyzeInitData(cfg *config.CocoConfig, secretCount int) Transformation {
	details := []string{
		"aa.toml: Attestation Agent configuration",
		fmt.Sprintf("  - Trustee KBS URL: %s", cfg.TrusteeServer),
		"cdh.toml: Confidential Data Hub configuration",
		"  - Enables secret retrieval from Trustee KBS",
	}

	if secretCount > 0 {
		details = append(details, fmt.Sprintf("  - %d secret(s) configured", secretCount))
	}

	details = append(details,
		"policy.rego: Kata Agent policy",
		"  - Controls guest operations (exec, logs, etc.)",
	)

	return Transformation{
		Type:        "initdata",
		Name:        "InitData Annotation",
		Description: "Generate and add initdata configuration annotation",
		Reason:      "Configures guest components for attestation and secure communication",
		Before:      "metadata:\n  annotations: {}",
		After:       "metadata:\n  annotations:\n    io.katacontainers.config.hypervisor.cc_init_data: |\n      H4sIAAAAAAAA/6yU...  ← GZIP-BASE64",
		Details:     details,
	}
}

func analyzeAnnotations(cfg *config.CocoConfig) Transformation {
	count := 0
	annotations := ""
	for key, value := range cfg.Annotations {
		if value != "" {
			count++
			annotations += fmt.Sprintf("\n    %s: \"%s\"", key, value)
		}
	}

	return Transformation{
		Type:        "annotation",
		Name:        "Custom Annotations",
		Description: fmt.Sprintf("Add %d custom annotation(s) from config", count),
		Reason:      "Apply user-defined Kata/CoCo configuration",
		Before:      "metadata:\n  annotations:\n    io.katacontainers.config.hypervisor.cc_init_data: ...",
		After:       "metadata:\n  annotations:\n    io.katacontainers.config.hypervisor.cc_init_data: ..." + annotations,
		Details: []string{
			"Defined in coco-config.toml [annotations] section",
			"Examples: machine_type, timeouts, kernel parameters",
		},
	}
}

func getChangeMarker(existing, updated string) string {
	if existing == "" {
		return "ADDED"
	}
	if existing != updated {
		return "UPDATED"
	}
	return "UNCHANGED"
}
