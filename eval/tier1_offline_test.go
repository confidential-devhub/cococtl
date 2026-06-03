package eval_test

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestEvalOffline runs all scenarios that do not require a Kubernetes cluster.
func TestEvalOffline(t *testing.T) {
	fx := fixtures(t)

	// ── explain ──────────────────────────────────────────────────────────────

	check(t, "offline", "explain/list-examples", func(t *testing.T) {
		out, _, code := runBin(t, "explain", "--list-examples")
		if code != 0 {
			t.Fatalf("exit %d", code)
		}
		if !strings.Contains(out, "simple-pod") {
			t.Errorf("expected 'simple-pod' in output:\n%s", out)
		}
	})

	check(t, "offline", "explain/example-text", func(t *testing.T) {
		out, _, code := runBin(t, "explain", "--example", "simple-pod")
		if code != 0 {
			t.Fatalf("exit %d", code)
		}
		if !strings.Contains(out, "kata-cc") {
			t.Errorf("expected 'kata-cc' in text output:\n%s", out)
		}
	})

	check(t, "offline", "explain/example-diff", func(t *testing.T) {
		out, _, code := runBin(t, "explain", "--example", "simple-pod", "--format", "diff")
		if code != 0 {
			t.Fatalf("exit %d", code)
		}
		if !strings.Contains(out, "kata-cc") {
			t.Errorf("expected 'kata-cc' in diff output:\n%s", out)
		}
	})

	check(t, "offline", "explain/example-markdown", func(t *testing.T) {
		out, _, code := runBin(t, "explain", "--example", "simple-pod", "--format", "markdown")
		if code != 0 {
			t.Fatalf("exit %d", code)
		}
		if !strings.Contains(out, "#") {
			t.Errorf("expected markdown headers in output:\n%s", out)
		}
	})

	check(t, "offline", "explain/local-manifest", func(t *testing.T) {
		src := filepath.Join(fx, "manifests", "simple-pod.yaml")
		_, _, code := runBin(t, "explain", "-f", src)
		if code != 0 {
			t.Fatalf("exit %d", code)
		}
	})

	// ── apply --skip-apply ────────────────────────────────────────────────────

	check(t, "offline", "apply/runtime-class", func(t *testing.T) {
		dir := t.TempDir()
		cfg := minimalConfig(t, dir)
		src := copyFixture(t, filepath.Join(fx, "manifests", "simple-pod.yaml"), dir)

		_, _, code := runBin(t, "apply", "-f", src, "--config", cfg, "--skip-apply", "--convert-secrets=false")
		if code != 0 {
			t.Fatalf("exit %d", code)
		}
		out, err := os.ReadFile(cocoOutput(src))
		if err != nil {
			t.Fatalf("output file missing: %v", err)
		}
		if !strings.Contains(string(out), "runtimeClassName: kata-cc") {
			t.Errorf("runtimeClassName not set:\n%s", out)
		}
	})

	check(t, "offline", "apply/initdata-annotation", func(t *testing.T) {
		dir := t.TempDir()
		cfg := minimalConfig(t, dir)
		src := copyFixture(t, filepath.Join(fx, "manifests", "simple-pod.yaml"), dir)

		runBin(t, "apply", "-f", src, "--config", cfg, "--skip-apply", "--convert-secrets=false")
		out, err := os.ReadFile(cocoOutput(src))
		if err != nil {
			t.Fatalf("output file missing: %v", err)
		}
		if !strings.Contains(string(out), "cc_init_data") {
			t.Errorf("cc_init_data annotation not found:\n%s", out)
		}
	})

	check(t, "offline", "apply/deployment-support", func(t *testing.T) {
		dir := t.TempDir()
		cfg := minimalConfig(t, dir)
		src := copyFixture(t, filepath.Join(fx, "manifests", "deployment.yaml"), dir)

		_, _, code := runBin(t, "apply", "-f", src, "--config", cfg, "--skip-apply", "--convert-secrets=false")
		if code != 0 {
			t.Fatalf("exit %d", code)
		}
		out, err := os.ReadFile(cocoOutput(src))
		if err != nil {
			t.Fatalf("output file missing: %v", err)
		}
		if !strings.Contains(string(out), "runtimeClassName: kata-cc") {
			t.Errorf("runtimeClassName not set in Deployment:\n%s", out)
		}
	})

	check(t, "offline", "apply/secret-warning", func(t *testing.T) {
		dir := t.TempDir()
		cfg := minimalConfig(t, dir)
		src := copyFixture(t, filepath.Join(fx, "manifests", "pod-with-secrets.yaml"), dir)

		stdout, stderr, _ := runBin(t, "apply", "-f", src, "--config", cfg, "--skip-apply", "--convert-secrets=false")
		combined := stdout + stderr
		if !strings.Contains(combined, "Warning") && !strings.Contains(combined, "sealed") {
			t.Errorf("expected secret warning; stdout+stderr:\n%s", combined)
		}
	})

	check(t, "offline", "apply/invalid-manifest-exits-nonzero", func(t *testing.T) {
		dir := t.TempDir()
		cfg := minimalConfig(t, dir)
		src := copyFixture(t, filepath.Join(fx, "manifests", "invalid.yaml"), dir)

		_, _, code := runBin(t, "apply", "-f", src, "--config", cfg, "--skip-apply")
		if code == 0 {
			t.Error("expected non-zero exit for invalid manifest")
		}
	})

	check(t, "offline", "apply/missing-file-exits-nonzero", func(t *testing.T) {
		dir := t.TempDir()
		cfg := minimalConfig(t, dir)

		_, _, code := runBin(t, "apply", "-f", filepath.Join(dir, "nonexistent.yaml"), "--config", cfg, "--skip-apply")
		if code == 0 {
			t.Error("expected non-zero exit for missing file")
		}
	})

	// ── initdata ─────────────────────────────────────────────────────────────

	check(t, "offline", "initdata/create", func(t *testing.T) {
		dir := t.TempDir()
		cfg := minimalConfig(t, dir)
		out := filepath.Join(dir, "initdata.toml")

		_, _, code := runBin(t, "initdata", "create", "--config", cfg, "--output", out)
		if code != 0 {
			t.Fatalf("exit %d", code)
		}
		if _, err := os.Stat(out); err != nil {
			t.Fatalf("output file not created: %v", err)
		}
	})

	check(t, "offline", "initdata/dump-encoded", func(t *testing.T) {
		dir := t.TempDir()
		cfg := minimalConfig(t, dir)
		tomlFile := filepath.Join(dir, "initdata.toml")
		runBin(t, "initdata", "create", "--config", cfg, "--output", tomlFile)

		stdout, _, code := runBin(t, "initdata", "dump", "--file", tomlFile)
		if code != 0 {
			t.Fatalf("exit %d", code)
		}
		if _, err := base64.StdEncoding.DecodeString(strings.TrimSpace(stdout)); err != nil {
			t.Errorf("output is not valid base64: %v\noutput: %s", err, stdout)
		}
	})

	check(t, "offline", "initdata/dump-raw", func(t *testing.T) {
		dir := t.TempDir()
		cfg := minimalConfig(t, dir)
		tomlFile := filepath.Join(dir, "initdata.toml")
		runBin(t, "initdata", "create", "--config", cfg, "--output", tomlFile)

		stdout, _, code := runBin(t, "initdata", "dump", "--file", tomlFile, "--raw")
		if code != 0 {
			t.Fatalf("exit %d", code)
		}
		if !strings.Contains(stdout, `"aa.toml"`) {
			t.Errorf("expected key \"aa.toml\" in raw dump:\n%s", stdout)
		}
	})

	check(t, "offline", "initdata/validate-valid", func(t *testing.T) {
		dir := t.TempDir()
		cfg := minimalConfig(t, dir)
		tomlFile := filepath.Join(dir, "initdata.toml")
		runBin(t, "initdata", "create", "--config", cfg, "--output", tomlFile)

		_, _, code := runBin(t, "initdata", "validate", "--file", tomlFile)
		if code != 0 {
			t.Fatalf("validate exited %d for valid initdata", code)
		}
	})

	check(t, "offline", "initdata/validate-invalid-exits-nonzero", func(t *testing.T) {
		dir := t.TempDir()
		bad := filepath.Join(dir, "bad.toml")
		_ = os.WriteFile(bad, []byte("[foo]\nbar = \"baz\"\n"), 0o644)

		_, _, code := runBin(t, "initdata", "validate", "--file", bad)
		if code == 0 {
			t.Error("expected non-zero exit for structurally invalid initdata")
		}
	})

	// ── completion ───────────────────────────────────────────────────────────

	check(t, "offline", "completion/bash", func(t *testing.T) {
		out, _, code := runBin(t, "completion", "bash")
		if code != 0 {
			t.Fatalf("exit %d", code)
		}
		if strings.TrimSpace(out) == "" {
			t.Error("expected non-empty bash completion output")
		}
	})

	check(t, "offline", "completion/zsh", func(t *testing.T) {
		out, _, code := runBin(t, "completion", "zsh")
		if code != 0 {
			t.Fatalf("exit %d", code)
		}
		if strings.TrimSpace(out) == "" {
			t.Error("expected non-empty zsh completion output")
		}
	})
}
