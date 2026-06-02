package eval_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const (
	evalPodName        = "coco-eval-test-pod"
	evalNamespace      = "default"
	evalRuntimeClass   = "kata-qemu-coco-dev"
)

// TestEvalCluster runs scenarios that require a live Kubernetes cluster.
func TestEvalCluster(t *testing.T) {
	if !clusterAvailable() {
		t.Skip("no Kubernetes cluster available — set KUBECONFIG or start a cluster to enable Tier 2")
	}

	check(t, "cluster", "cluster/api-reachable", func(t *testing.T) {
		out, err := exec.Command("kubectl", "cluster-info").Output()
		if err != nil {
			t.Fatalf("kubectl cluster-info: %v", err)
		}
		if !strings.Contains(string(out), "control plane") && !strings.Contains(string(out), "Kubernetes") {
			t.Errorf("unexpected cluster-info output:\n%s", out)
		}
	})

	check(t, "cluster", "cluster/apply-creates-object", func(t *testing.T) {
		// kata-qemu-coco-dev RuntimeClass is required; skip on plain clusters.
		if out, err := exec.Command("kubectl", "get", "runtimeclass", evalRuntimeClass, "-o", "name").Output(); err != nil || !strings.Contains(string(out), evalRuntimeClass) {
			t.Skipf("%s RuntimeClass not found — install CoCo (`helm install coco oci://ghcr.io/confidential-containers/charts/confidential-containers`) to enable this test", evalRuntimeClass)
		}

		dir := t.TempDir()
		cfg := minimalConfig(t, dir)
		src := copyFixture(t, filepath.Join(fixtures(t), "manifests", "simple-pod.yaml"), dir)

		data, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		patched := strings.ReplaceAll(string(data), "name: test-pod", "name: "+evalPodName)
		if err := os.WriteFile(src, []byte(patched), 0o644); err != nil {
			t.Fatal(err)
		}

		t.Cleanup(func() {
			exec.Command("kubectl", "delete", "pod", evalPodName, "-n", evalNamespace, "--ignore-not-found=true", "--timeout=30s").Run() //nolint:errcheck
		})

		_, _, code := runBin(t, "apply", "-f", src, "--config", cfg,
			"--convert-secrets=false", "--runtime-class", evalRuntimeClass, "-n", evalNamespace)
		if code != 0 {
			t.Fatalf("apply exited %d", code)
		}

		out, err := exec.Command("kubectl", "get", "pod", evalPodName, "-n", evalNamespace, "-o", "name").Output()
		if err != nil || !strings.Contains(string(out), evalPodName) {
			t.Errorf("pod %s not found after apply (err=%v, out=%s)", evalPodName, err, out)
		}
	})

	check(t, "cluster", "cluster/kbs-detect-or-skip", func(t *testing.T) {
		out, err := exec.Command("kubectl", "get", "pods", "-l", "app=trustee", "-o", "name").Output()
		if err != nil || strings.TrimSpace(string(out)) == "" {
			t.Skip("no Trustee pod found — deploy with `kubectl coco kbs start` to enable KBS tests")
		}
		_, _, code := runBin(t, "kbs", "--help")
		if code != 0 {
			t.Fatalf("kbs --help exited %d", code)
		}
	})
}
