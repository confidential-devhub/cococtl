package sealed

import (
	"fmt"
	"os/exec"
	"strings"
)

const (
	// CocoToolsImage is the default image for coco-tools
	CocoToolsImage = "quay.io/confidential-devhub/coco-tools:0.4.0"

	// ContainerRuntime preferences (try in order)
	runtimePodman = "podman"
	runtimeDocker = "docker"
)

// ConvertToSealed converts a resource URI to a sealed secret using coco-tools
// Returns the sealed secret string (sealed.fakejwsheader.xxx.fakesignature)
func ConvertToSealed(resourceURI string) (string, error) {
	if resourceURI == "" {
		return "", fmt.Errorf("resource URI cannot be empty")
	}

	// Detect available container runtime
	runtime, err := detectRuntime()
	if err != nil {
		return "", fmt.Errorf("no container runtime found: %w", err)
	}

	// Run coco-tools to generate sealed secret
	// podman run -it quay.io/confidential-devhub/coco-tools:0.4.0 /tools/secret seal vault --resource-uri kbs:///default/kbsres1/key1 --provider kbs
	cmd := exec.Command(
		runtime,
		"run",
		"--rm",
		CocoToolsImage,
		"/tools/secret",
		"seal",
		"vault",
		"--resource-uri", resourceURI,
		"--provider", "kbs",
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to run coco-tools: %w\nOutput: %s", err, string(output))
	}

	// Parse output to extract sealed secret
	// Expected format:
	// Warning: Secrets must be provisioned to provider separately.
	// sealed.fakejwsheader.eyJ2ZXJzaW...fakesignature
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "sealed.") {
			return trimmed, nil
		}
	}

	return "", fmt.Errorf("failed to extract sealed secret from output: %s", string(output))
}

// detectRuntime checks which container runtime is available
func detectRuntime() (string, error) {
	// Try podman first
	if _, err := exec.LookPath(runtimePodman); err == nil {
		return runtimePodman, nil
	}

	// Try docker
	if _, err := exec.LookPath(runtimeDocker); err == nil {
		return runtimeDocker, nil
	}

	return "", fmt.Errorf("neither podman nor docker found in PATH")
}

// GetRuntime returns the detected container runtime
func GetRuntime() (string, error) {
	return detectRuntime()
}
