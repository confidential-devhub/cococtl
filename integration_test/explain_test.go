package integration_test

import (
	"os"
	"strings"
	"testing"

	"github.com/confidential-devhub/cococtl/pkg/config"
	"github.com/confidential-devhub/cococtl/pkg/examples"
	"github.com/confidential-devhub/cococtl/pkg/explain"
)

func getTestConfig() *config.CocoConfig {
	return &config.CocoConfig{
		TrusteeServer: "http://trustee-kbs.default.svc.cluster.local:8080",
		RuntimeClass:  "kata-cc",
		Sidecar: config.SidecarConfig{
			Enabled:   false,
			HTTPSPort: 8443,
			Image:     "ghcr.io/confidential-containers/sidecar:latest",
		},
		Annotations: map[string]string{
			"io.katacontainers.config.hypervisor.machine_type": "q35",
		},
	}
}

// Test analyzing a simple pod manifest
func TestExplain_AnalyzeSimplePod(t *testing.T) {
	cfg := getTestConfig()
	analysis, err := explain.Analyze("testdata/manifests/pod-simple.yaml", cfg, false, 0)
	if err != nil {
		t.Fatalf("Failed to analyze manifest: %v", err)
	}

	if analysis.ResourceKind != "Pod" {
		t.Errorf("Expected resource kind Pod, got %s", analysis.ResourceKind)
	}

	if analysis.ResourceName != "nginx" {
		t.Errorf("Expected resource name nginx, got %s", analysis.ResourceName)
	}

	// Should have at least RuntimeClass and InitData transformations
	if len(analysis.Transformations) < 2 {
		t.Errorf("Expected at least 2 transformations, got %d", len(analysis.Transformations))
	}

	// Verify RuntimeClass transformation exists
	hasRuntimeClass := false
	for _, tr := range analysis.Transformations {
		if tr.Type == "runtime" {
			hasRuntimeClass = true
			if tr.Name != "RuntimeClass Configuration" {
				t.Errorf("Expected RuntimeClass Configuration, got %s", tr.Name)
			}
		}
	}
	if !hasRuntimeClass {
		t.Error("RuntimeClass transformation not found")
	}
}

// Test analyzing a pod with secrets
func TestExplain_AnalyzePodWithSecrets(t *testing.T) {
	cfg := getTestConfig()
	analysis, err := explain.Analyze("testdata/manifests/pod-with-secrets.yaml", cfg, false, 0)
	if err != nil {
		t.Fatalf("Failed to analyze manifest: %v", err)
	}

	if analysis.ResourceKind != "Pod" {
		t.Errorf("Expected resource kind Pod, got %s", analysis.ResourceKind)
	}

	if analysis.SecretCount < 2 {
		t.Errorf("Expected at least 2 secrets to be detected, got %d", analysis.SecretCount)
	}

	// Should have secret transformations
	hasSecretTransform := false
	for _, tr := range analysis.Transformations {
		if tr.Type == "secret" {
			hasSecretTransform = true
			if !strings.Contains(tr.Before, "secretKeyRef") && !strings.Contains(tr.Before, "secret:") {
				t.Errorf("Secret transformation should show original secret reference, got: %s", tr.Before)
			}
		}
	}
	if !hasSecretTransform {
		t.Error("Secret transformation not found")
	}
}

// Test analyzing with sidecar enabled
func TestExplain_AnalyzeWithSidecar(t *testing.T) {
	cfg := getTestConfig()
	// Use manifest with service (port 8080)
	analysis, err := explain.Analyze("testdata/manifests/pod-with-service.yaml", cfg, true, 0)
	if err != nil {
		t.Fatalf("Failed to analyze manifest: %v", err)
	}

	if !analysis.SidecarEnabled {
		t.Error("Expected sidecar to be enabled")
	}

	if !analysis.HasService {
		t.Error("Expected service to be detected")
	}

	if analysis.ServicePort != 8080 {
		t.Errorf("Expected service port 8080, got %d", analysis.ServicePort)
	}

	// Should have sidecar transformation
	hasSidecarTransform := false
	for _, tr := range analysis.Transformations {
		if tr.Type == "sidecar" {
			hasSidecarTransform = true
			if !strings.Contains(tr.After, "coco-secure-access") {
				t.Error("Sidecar transformation should mention coco-secure-access container")
			}
			if !strings.Contains(tr.Description, "8080") {
				t.Error("Sidecar transformation should mention the forwarded port")
			}
		}
	}
	if !hasSidecarTransform {
		t.Error("Sidecar transformation not found")
	}
}

// Test analyzing with manual sidecar port
func TestExplain_AnalyzeWithManualSidecarPort(t *testing.T) {
	cfg := getTestConfig()
	analysis, err := explain.Analyze("testdata/manifests/pod-simple.yaml", cfg, true, 9090)
	if err != nil {
		t.Fatalf("Failed to analyze manifest: %v", err)
	}

	if !analysis.SidecarEnabled {
		t.Error("Expected sidecar to be enabled")
	}

	// Should have sidecar transformation with manual port
	hasSidecarTransform := false
	for _, tr := range analysis.Transformations {
		if tr.Type == "sidecar" {
			hasSidecarTransform = true
			if !strings.Contains(tr.Description, "9090") {
				t.Error("Sidecar transformation should mention manual port 9090")
			}
		}
	}
	if !hasSidecarTransform {
		t.Error("Sidecar transformation not found")
	}
}

// Test analyzing with custom annotations
func TestExplain_AnalyzeWithAnnotations(t *testing.T) {
	cfg := getTestConfig()
	cfg.Annotations = map[string]string{
		"io.katacontainers.config.hypervisor.machine_type": "q35",
		"io.katacontainers.config.hypervisor.kernel":       "/opt/kata/vmlinuz",
	}

	analysis, err := explain.Analyze("testdata/manifests/pod-simple.yaml", cfg, false, 0)
	if err != nil {
		t.Fatalf("Failed to analyze manifest: %v", err)
	}

	// Should have annotation transformation
	hasAnnotationTransform := false
	for _, tr := range analysis.Transformations {
		if tr.Type == "annotation" {
			hasAnnotationTransform = true
			if !strings.Contains(tr.After, "machine_type") {
				t.Error("Annotation transformation should include machine_type")
			}
		}
	}
	if !hasAnnotationTransform {
		t.Error("Annotation transformation not found")
	}
}

// Test text format output
func TestExplain_FormatText(t *testing.T) {
	cfg := getTestConfig()
	analysis, err := explain.Analyze("testdata/manifests/pod-simple.yaml", cfg, false, 0)
	if err != nil {
		t.Fatalf("Failed to analyze manifest: %v", err)
	}

	output := explain.FormatText(analysis)

	// Check for key sections
	if !strings.Contains(output, "📋 Analyzing manifest") {
		t.Error("Text output should contain header")
	}
	if !strings.Contains(output, "🔍 Detected Resources:") {
		t.Error("Text output should contain detected resources section")
	}
	if !strings.Contains(output, "📝 Transformations Required:") {
		t.Error("Text output should contain transformations section")
	}
	if !strings.Contains(output, "✅ Summary:") {
		t.Error("Text output should contain summary section")
	}
	if !strings.Contains(output, "RuntimeClass Configuration") {
		t.Error("Text output should contain RuntimeClass transformation")
	}
}

// Test diff format output
func TestExplain_FormatDiff(t *testing.T) {
	cfg := getTestConfig()
	analysis, err := explain.Analyze("testdata/manifests/pod-simple.yaml", cfg, false, 0)
	if err != nil {
		t.Fatalf("Failed to analyze manifest: %v", err)
	}

	output := explain.FormatDiff(analysis)

	// Check for diff format elements
	if !strings.Contains(output, "BEFORE") {
		t.Error("Diff output should contain BEFORE column")
	}
	if !strings.Contains(output, "AFTER") {
		t.Error("Diff output should contain AFTER column")
	}
	if !strings.Contains(output, "│") {
		t.Error("Diff output should contain column separator")
	}
	if !strings.Contains(output, "RuntimeClass Configuration") {
		t.Error("Diff output should contain transformation names")
	}
}

// Test markdown format output
func TestExplain_FormatMarkdown(t *testing.T) {
	cfg := getTestConfig()
	analysis, err := explain.Analyze("testdata/manifests/pod-simple.yaml", cfg, false, 0)
	if err != nil {
		t.Fatalf("Failed to analyze manifest: %v", err)
	}

	output := explain.FormatMarkdown(analysis)

	// Check for markdown elements
	if !strings.HasPrefix(output, "# CoCo Transformation Analysis:") {
		t.Error("Markdown output should start with h1 header")
	}
	if !strings.Contains(output, "## 📋 Resources") {
		t.Error("Markdown output should contain resources section")
	}
	if !strings.Contains(output, "## 📝 Transformations") {
		t.Error("Markdown output should contain transformations section")
	}
	if !strings.Contains(output, "## ✅ Summary") {
		t.Error("Markdown output should contain summary section")
	}
	if !strings.Contains(output, "```yaml") {
		t.Error("Markdown output should contain YAML code blocks")
	}
	if !strings.Contains(output, "**Before**:") {
		t.Error("Markdown output should contain Before sections")
	}
	if !strings.Contains(output, "**After**:") {
		t.Error("Markdown output should contain After sections")
	}
}

// Test example loading
func TestExplain_ExampleLoading(t *testing.T) {
	testCases := []struct {
		name        string
		expectFound bool
	}{
		{"simple-pod", true},
		{"deployment-secrets", true},
		{"sidecar-service", true},
		{"nonexistent", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ex := examples.Get(tc.name)
			if tc.expectFound {
				if ex == nil {
					t.Errorf("Expected example %s to be found", tc.name)
				} else {
					// Note: ex.Name is the display name (e.g., "Simple Pod"), not the key
					if ex.Manifest == "" {
						t.Error("Example manifest should not be empty")
					}
					if ex.Description == "" {
						t.Error("Example description should not be empty")
					}
					if ex.Scenario == "" {
						t.Error("Example scenario should not be empty")
					}
				}
			} else {
				if ex != nil {
					t.Errorf("Expected example %s to not be found", tc.name)
				}
			}
		})
	}
}

// Test example list
func TestExplain_ExampleList(t *testing.T) {
	names := examples.List()
	if len(names) == 0 {
		t.Error("Expected at least one example")
	}

	// Check for known examples
	expectedExamples := map[string]bool{
		"simple-pod":         false,
		"deployment-secrets": false,
		"sidecar-service":    false,
	}

	for _, name := range names {
		if _, exists := expectedExamples[name]; exists {
			expectedExamples[name] = true
		}
	}

	for name, found := range expectedExamples {
		if !found {
			t.Errorf("Expected example %s not found in list", name)
		}
	}
}

// Test analyzing deployment with vLLM (complex real-world example)
func TestExplain_AnalyzeVLLMDeployment(t *testing.T) {
	cfg := getTestConfig()
	analysis, err := explain.Analyze("testdata/manifests/deployment-with-service-vllm.yaml", cfg, true, 0)
	if err != nil {
		t.Fatalf("Failed to analyze vLLM manifest: %v", err)
	}

	if analysis.ResourceKind != "Deployment" {
		t.Errorf("Expected resource kind Deployment, got %s", analysis.ResourceKind)
	}

	if analysis.ResourceName != "vllm" {
		t.Errorf("Expected resource name vllm, got %s", analysis.ResourceName)
	}

	if !analysis.HasService {
		t.Error("Expected service to be detected")
	}

	if !analysis.SidecarEnabled {
		t.Error("Expected sidecar to be enabled")
	}

	// vLLM deployment doesn't have secrets in this example
	// But should have multiple transformations (RuntimeClass, Sidecar, InitData, Annotations)
	if len(analysis.Transformations) < 3 {
		t.Errorf("Expected at least 3 transformations for vLLM, got %d", len(analysis.Transformations))
	}
}

// Test error handling for invalid manifest
func TestExplain_AnalyzeInvalidManifest(t *testing.T) {
	cfg := getTestConfig()
	_, err := explain.Analyze("testdata/manifests/nonexistent.yaml", cfg, false, 0)
	if err == nil {
		t.Error("Expected error for nonexistent manifest")
	}
}

// Test analyzing manifest with no workload (only ConfigMap)
func TestExplain_AnalyzeNoWorkload(t *testing.T) {
	cfg := getTestConfig()
	_, err := explain.Analyze("testdata/manifests/configmap-only.yaml", cfg, false, 0)
	if err == nil {
		t.Error("Expected error for manifest with no workload")
	}
	if err != nil && !strings.Contains(err.Error(), "no workload manifest") {
		t.Errorf("Expected 'no workload manifest' error, got: %v", err)
	}
}

// Test example config loading
func TestExplain_ExampleConfig(t *testing.T) {
	configPath, err := examples.GetExampleConfigPath()
	if err != nil {
		t.Fatalf("Failed to get example config path: %v", err)
	}
	defer func() {
		_ = os.Remove(configPath) // Best effort cleanup
	}()

	// Verify the config path exists
	if _, err := os.Stat(configPath); err != nil {
		t.Errorf("Example config file should exist at %s: %v", configPath, err)
	}

	// Verify we can load the config
	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load example config: %v", err)
	}

	// Verify config has expected values
	if cfg.TrusteeServer == "" {
		t.Error("Example config should have TrusteeServer set")
	}
	if cfg.RuntimeClass == "" {
		t.Error("Example config should have RuntimeClass set")
	}
	if cfg.RuntimeClass != "kata-cc" {
		t.Errorf("Expected RuntimeClass kata-cc, got %s", cfg.RuntimeClass)
	}
}
