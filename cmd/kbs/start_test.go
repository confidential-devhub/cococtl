package kbs

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/confidential-devhub/cococtl/pkg/config"
)

func newTestCmd() *cobra.Command {
	return &cobra.Command{}
}

// withHome redirects HOME to a temp dir and clears kubeconfig env vars so
// tests are hermetic: no developer or CI kubeconfig can influence code paths.
func withHome(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("KUBECONFIG", "")
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	t.Setenv("KUBERNETES_SERVICE_PORT", "")
	t.Cleanup(func() {
		startURL = ""
		startAuthDir = ""
	})
	return dir
}

func TestRunStartExternal_ErrorWhenURLMissing(t *testing.T) {
	withHome(t)
	startURL = ""

	err := runStartExternal(newTestCmd())
	if err == nil {
		t.Fatal("expected error when --url is missing, got nil")
	}
	if !strings.Contains(err.Error(), "--url") {
		t.Errorf("error %q should mention --url", err.Error())
	}
}

func TestRunStartExternal_PersistsURLToConfig(t *testing.T) {
	home := withHome(t)
	startURL = "http://kbs.example.com:8080"
	startAuthDir = ""

	if err := runStartExternal(newTestCmd()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Config should have been written to $HOME/.kube/coco-config.toml
	cfgPath := filepath.Join(home, ".kube", "coco-config.toml")
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("failed to load written config: %v", err)
	}
	if cfg.TrusteeServer != startURL {
		t.Errorf("TrusteeServer = %q, want %q", cfg.TrusteeServer, startURL)
	}
}

func TestRunStartExternal_PersistsAuthDirToConfig(t *testing.T) {
	home := withHome(t)
	startURL = "http://kbs.example.com:8080"
	startAuthDir = filepath.Join(home, "my-auth")

	if err := runStartExternal(newTestCmd()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cfgPath := filepath.Join(home, ".kube", "coco-config.toml")
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("failed to load written config: %v", err)
	}
	if cfg.KBSAuthDir != startAuthDir {
		t.Errorf("KBSAuthDir = %q, want %q", cfg.KBSAuthDir, startAuthDir)
	}
}

func TestRunStartExternal_PersistsBothURLAndAuthDir(t *testing.T) {
	home := withHome(t)
	startURL = "http://kbs.example.com:8080"
	startAuthDir = filepath.Join(home, "my-auth")

	if err := runStartExternal(newTestCmd()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cfgPath := filepath.Join(home, ".kube", "coco-config.toml")
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("failed to load written config: %v", err)
	}
	if cfg.TrusteeServer != startURL {
		t.Errorf("TrusteeServer = %q, want %q", cfg.TrusteeServer, startURL)
	}
	if cfg.KBSAuthDir != startAuthDir {
		t.Errorf("KBSAuthDir = %q, want %q", cfg.KBSAuthDir, startAuthDir)
	}
}

func TestRunStartExternal_ErrorWhenURLHasNoScheme(t *testing.T) {
	withHome(t)
	startURL = "kbs.example.com:8080"

	err := runStartExternal(newTestCmd())
	if err == nil {
		t.Fatal("expected error for URL without scheme, got nil")
	}
	if !strings.Contains(err.Error(), "http") {
		t.Errorf("error %q should mention http/https", err.Error())
	}
}

func TestRunStartExternal_ErrorWhenURLHasSchemeButEmptyHost(t *testing.T) {
	withHome(t)
	startURL = "http://"

	err := runStartExternal(newTestCmd())
	if err == nil {
		t.Fatal("expected error for URL with scheme but empty host, got nil")
	}
	if !strings.Contains(err.Error(), "http") {
		t.Errorf("error %q should mention http/https", err.Error())
	}
}
