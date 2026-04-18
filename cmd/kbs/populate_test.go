package kbs

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-devhub/cococtl/pkg/config"
)

// writeConfig writes a minimal CocoConfig to $HOME/.kube/coco-config.toml.
func writeConfig(t *testing.T, home string, cfg *config.CocoConfig) {
	t.Helper()
	cfgPath := filepath.Join(home, ".kube", "coco-config.toml")
	if err := cfg.Save(cfgPath); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}
}

// resetPopulateFlags clears package-level populate flag vars between tests.
func resetPopulateFlags(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		populateKBSURL = ""
		populateAuthKey = ""
		populateAuthDir = ""
	})
	populateKBSURL = ""
	populateAuthKey = ""
	populateAuthDir = ""
}

// TestCreatePopulateKBSClient_ConfigExternalURL verifies that a valid non-cluster
// TrusteeServer in config triggers direct-connect mode. withHome clears KUBECONFIG
// so the port-forward path would fail at k8s.NewClient, not at private-key loading;
// the direct-connect path fails at private-key loading. We assert on the latter.
func TestCreatePopulateKBSClient_ConfigExternalURL(t *testing.T) {
	home := withHome(t)
	resetPopulateFlags(t)

	cfg := config.DefaultConfig()
	cfg.TrusteeServer = "http://kbs.example.com:8080"
	writeConfig(t, home, cfg)

	_, stop, err := createPopulateKBSClient(context.Background())
	stop()

	if err == nil {
		t.Fatal("expected error (no private key on disk), got nil")
	}
	// Direct-connect path fails here: key file not found.
	if !strings.HasPrefix(err.Error(), "failed to read KBS private key") {
		t.Errorf("expected direct-connect key-load error, got: %v", err)
	}
}

// TestCreatePopulateKBSClient_InvalidConfigURL verifies that a malformed
// TrusteeServer URL falls through to port-forward mode. withHome clears KUBECONFIG
// so the port-forward path reliably fails at k8s.NewClient ("failed to create
// Kubernetes client") before reaching private-key loading, giving a clean signal.
func TestCreatePopulateKBSClient_InvalidConfigURL(t *testing.T) {
	home := withHome(t)
	resetPopulateFlags(t)

	cfg := config.DefaultConfig()
	cfg.TrusteeServer = "http://" // valid scheme, empty host — must be rejected
	writeConfig(t, home, cfg)

	_, stop, err := createPopulateKBSClient(context.Background())
	stop()

	if err == nil {
		t.Fatal("expected error (no cluster), got nil")
	}
	// The port-forward path always wraps its errors with "failed to connect to KBS
	// via port-forward". The direct-connect path returns the raw key-load error
	// without that prefix. Assert the raw prefix is absent to confirm we did NOT
	// take direct-connect with the bad URL.
	if strings.HasPrefix(err.Error(), "failed to read KBS private key") {
		t.Errorf("invalid URL should fall through to port-forward, not direct-connect: %v", err)
	}
}
