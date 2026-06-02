package eval_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	evalPodName      = "coco-eval-test-pod"
	evalNamespace    = "coco-eval"
	evalRuntimeClass = "kata-qemu-coco-dev"
)

// TestEvalCluster drives the full user workflow against a live cluster:
//
//	kbs start → kbs populate → apply (with secrets) → apply (with kata runtime)
func TestEvalCluster(t *testing.T) {
	if !clusterAvailable() {
		t.Skip("no Kubernetes cluster available — set KUBECONFIG or start a cluster to enable Tier 2")
	}

	// Isolated namespace; deleted on cleanup.
	createEvalNamespace(t)
	// Config is overwritten by kbs start; restore original on cleanup.
	backupCocoConfig(t)

	// ── connectivity ──────────────────────────────────────────────────────────

	check(t, "cluster", "cluster/api-reachable", func(t *testing.T) {
		out, err := exec.Command("kubectl", "cluster-info").Output()
		if err != nil {
			t.Fatalf("kubectl cluster-info: %v", err)
		}
		if !strings.Contains(string(out), "control plane") && !strings.Contains(string(out), "Kubernetes") {
			t.Errorf("unexpected cluster-info output:\n%s", out)
		}
	})

	// ── init (Day 1 command) ─────────────────────────────────────────────────

	check(t, "cluster", "cluster/init", func(t *testing.T) {
		stdout, stderr, code := runBin(t, "init", "--trustee-namespace", evalNamespace)
		if code != 0 {
			t.Fatalf("init exited %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
		}
		home, _ := os.UserHomeDir()
		cfgPath := filepath.Join(home, ".kube", "coco-config.toml")
		cfgData, err := os.ReadFile(cfgPath)
		if err != nil {
			t.Fatalf("config not created at %s: %v", cfgPath, err)
		}
		if !strings.Contains(string(cfgData), "trustee_server") ||
			strings.Contains(string(cfgData), "trustee_server = ''") {
			t.Fatalf("config missing trustee_server:\n%s", cfgData)
		}
		// Trustee pod must be ready before KBS tests proceed.
		if out, err := exec.Command("kubectl", "wait", "--for=condition=ready",
			"pod", "-l", "app=kbs", "-n", evalNamespace, "--timeout=120s",
		).CombinedOutput(); err != nil {
			t.Fatalf("Trustee not ready: %v\n%s", err, out)
		}
	})

	// ── KBS workflow ──────────────────────────────────────────────────────────

	check(t, "cluster", "cluster/kbs-start", func(t *testing.T) {
		stdout, stderr, code := runBin(t, "kbs", "start", "--namespace", evalNamespace)
		if code != 0 {
			t.Fatalf("kbs start exited %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
		}
		// Wait specifically for the Trustee pod; --all would block on any
		// Terminating pod left over from a rolling update.
		out, err := exec.Command(
			"kubectl", "wait", "--for=condition=ready", "pod", "-l", "app=kbs",
			"-n", evalNamespace, "--timeout=120s",
		).CombinedOutput()
		if err != nil {
			t.Fatalf("Trustee pod not ready: %v\n%s", err, out)
		}
	})

	check(t, "cluster", "cluster/kbs-populate", func(t *testing.T) {
		resFile := filepath.Join(t.TempDir(), "resource.txt")
		if err := os.WriteFile(resFile, []byte("eval-test-secret-value"), 0o644); err != nil {
			t.Fatal(err)
		}
		stdout, stderr, code := runBin(t, "kbs", "populate",
			"--path", "default/eval/test-resource",
			"--resource-file", resFile,
			"--namespace", evalNamespace,
		)
		if code != 0 {
			t.Fatalf("kbs populate exited %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
		}
	})

	// ── apply workflow ────────────────────────────────────────────────────────

	check(t, "cluster", "cluster/kbs-content-verify", func(t *testing.T) {
		// Confirm the resource uploaded by kbs-populate is stored in the KBS
		// repository on disk inside the Trustee pod.
		const repoBase = "/opt/confidential-containers/kbs/repository"
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, "kubectl", "exec",
			"-n", evalNamespace, "deployment/trustee-deployment", "--",
			"test", "-f", repoBase+"/default/eval/test-resource",
		).CombinedOutput()
		if err != nil {
			t.Fatalf("resource not found in KBS repository: %v\n%s", err, out)
		}
	})

	check(t, "cluster", "cluster/kbs-populate-from-k8s-secret", func(t *testing.T) {
		// Create a K8s secret then upload it via the --from-k8s-secret input mode.
		genOut, err := exec.Command("kubectl", "create", "secret", "generic", "eval-kbs-upload-secret",
			"--from-literal=api-key=top-secret-value",
			"-n", evalNamespace, "--dry-run=client", "-o", "yaml",
		).Output()
		if err != nil {
			t.Fatalf("generate secret YAML: %v", err)
		}
		ap := exec.Command("kubectl", "apply", "-f", "-")
		ap.Stdin = strings.NewReader(string(genOut))
		if out, err := ap.CombinedOutput(); err != nil {
			t.Fatalf("kubectl apply secret: %v\n%s", err, out)
		}

		stdout, stderr, code := runBin(t, "kbs", "populate",
			"--from-k8s-secret", "eval-kbs-upload-secret",
			"--namespace", evalNamespace,
		)
		if code != 0 {
			t.Fatalf("kbs populate exited %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
		}
		// Verify the secret key actually landed in the KBS repository on disk.
		// Path: <namespace>/<secret-name>/<key>
		const repoBase = "/opt/confidential-containers/kbs/repository"
		if out, err := exec.Command("kubectl", "exec",
			"-n", evalNamespace, "deployment/trustee-deployment", "--",
			"test", "-f", repoBase+"/"+evalNamespace+"/eval-kbs-upload-secret/api-key",
		).CombinedOutput(); err != nil {
			t.Fatalf("secret not found in KBS repository: %v\n%s", err, out)
		}
	})

	check(t, "cluster", "cluster/apply-transforms-with-secrets", func(t *testing.T) {
		// Create a K8s secret in the eval namespace that the pod will reference.
		if out, err := exec.Command("kubectl", "create", "secret", "generic", "eval-app-secret",
			"--from-literal=password=super-secret-value",
			"-n", evalNamespace, "--dry-run=client", "-o", "yaml",
		).Output(); err != nil {
			t.Fatalf("generate secret YAML: %v", err)
		} else {
			ap := exec.Command("kubectl", "apply", "-f", "-")
			ap.Stdin = strings.NewReader(string(out))
			if combined, err := ap.CombinedOutput(); err != nil {
				t.Fatalf("kubectl apply secret: %v\n%s", err, combined)
			}
		}

		// Write a minimal pod manifest referencing the secret.
		dir := t.TempDir()
		podFile := filepath.Join(dir, "pod.yaml")
		// Embed the namespace so the generated trustee-secrets file records the
		// correct namespace for the KBS path and K8s secret lookup.
		if err := os.WriteFile(podFile, []byte(`apiVersion: v1
kind: Pod
metadata:
  name: eval-secrets-pod
  namespace: `+evalNamespace+`
spec:
  containers:
  - name: app
    image: nginx:latest
    env:
    - name: PASSWORD
      valueFrom:
        secretKeyRef:
          name: eval-app-secret
          key: password
`), 0o644); err != nil {
			t.Fatal(err)
		}

		// --skip-apply: apply transforms the manifest and writes two sidecar files:
		//   pod-sealed-secrets.yaml  — K8s Secret manifest (kubectl apply separately)
		//   pod-trustee-secrets.yaml — for `kbs populate -f` to upload values to KBS
		// KBS upload is NOT performed automatically; it is deferred to the user.
		// We run kbs populate here to close that gap and then verify via kubectl exec.
		stdout, stderr, code := runBin(t, "apply", "-f", podFile,
			"--skip-apply", "-n", evalNamespace,
		)
		if code != 0 {
			t.Fatalf("apply exited %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
		}

		coco, err := os.ReadFile(cocoOutput(podFile))
		if err != nil {
			t.Fatalf("output file missing: %v", err)
		}
		if !strings.Contains(string(coco), "-sealed") {
			t.Errorf("sealed secret suffix not found in -coco.yaml:\n%s", coco)
		}

		// Upload the generated trustee-secrets file so KBS actually has the data.
		trusteeSecrets := strings.TrimSuffix(podFile, ".yaml") + "-trustee-secrets.yaml"
		if _, err := os.Stat(trusteeSecrets); err != nil {
			t.Fatalf("trustee-secrets file not generated at %s: %v", trusteeSecrets, err)
		}
		if stdout, stderr, code = runBin(t, "kbs", "populate",
			"-f", trusteeSecrets, "--namespace", evalNamespace,
		); code != 0 {
			t.Fatalf("kbs populate exited %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
		}

		// Confirm the secret value landed in the KBS repository on disk.
		const repoBase = "/opt/confidential-containers/kbs/repository"
		if out, err := exec.Command("kubectl", "exec",
			"-n", evalNamespace, "deployment/trustee-deployment", "--",
			"test", "-f", repoBase+"/"+evalNamespace+"/eval-app-secret/password",
		).CombinedOutput(); err != nil {
			t.Fatalf("secret not found in KBS repository: %v\n%s", err, out)
		}
	})

	check(t, "cluster", "cluster/apply-init-container", func(t *testing.T) {
		dir := t.TempDir()
		src := copyFixture(t, filepath.Join(fixtures(t), "manifests", "simple-pod.yaml"), dir)

		stdout, stderr, code := runBin(t, "apply", "-f", src,
			"--skip-apply", "--init-container", "--convert-secrets=false", "-n", evalNamespace,
		)
		if code != 0 {
			t.Fatalf("apply exited %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
		}
		out, err := os.ReadFile(cocoOutput(src))
		if err != nil {
			t.Fatalf("output file missing: %v", err)
		}
		if !strings.Contains(string(out), "initContainers:") {
			t.Errorf("initContainers not found in -coco.yaml:\n%s", out)
		}
	})

	check(t, "cluster", "cluster/apply-creates-pod", func(t *testing.T) {
		// Skip if kata-qemu-coco-dev is not installed on this cluster.
		if out, err := exec.Command("kubectl", "get", "runtimeclass", evalRuntimeClass, "-o", "name").Output(); err != nil || !strings.Contains(string(out), evalRuntimeClass) {
			t.Skipf("%s RuntimeClass not found — helm install coco oci://ghcr.io/confidential-containers/charts/confidential-containers", evalRuntimeClass)
		}

		dir := t.TempDir()
		src := copyFixture(t, filepath.Join(fixtures(t), "manifests", "simple-pod.yaml"), dir)

		data, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		// Rename the pod and embed the eval namespace so kubectl apply targets
		// coco-eval rather than the kubeconfig default namespace.
		patched := strings.ReplaceAll(string(data), "name: test-pod", "name: "+evalPodName)
		patched = strings.Replace(patched, "metadata:", "metadata:\n  namespace: "+evalNamespace, 1)
		if err := os.WriteFile(src, []byte(patched), 0o644); err != nil {
			t.Fatal(err)
		}

		t.Cleanup(func() {
			exec.Command("kubectl", "delete", "pod", evalPodName, "-n", evalNamespace, "--ignore-not-found=true", "--timeout=30s").Run() //nolint:errcheck
		})

		_, _, code := runBin(t, "apply", "-f", src,
			"--convert-secrets=false", "--runtime-class", evalRuntimeClass, "-n", evalNamespace,
		)
		if code != 0 {
			t.Fatalf("apply exited %d", code)
		}

		out, err := exec.Command("kubectl", "get", "pod", evalPodName, "-n", evalNamespace, "-o", "name").Output()
		if err != nil || !strings.Contains(string(out), evalPodName) {
			t.Errorf("pod not found in %s after apply: err=%v, out=%s", evalNamespace, err, out)
		}
		// Verify the transformation actually set runtimeClassName on the pod spec.
		rcOut, err := exec.Command("kubectl", "get", "pod", evalPodName, "-n", evalNamespace,
			"-o", "jsonpath={.spec.runtimeClassName}").Output()
		if err != nil || strings.TrimSpace(string(rcOut)) != evalRuntimeClass {
			t.Errorf("runtimeClassName not set correctly: err=%v, got=%q, want=%q",
				err, strings.TrimSpace(string(rcOut)), evalRuntimeClass)
		}
	})
	check(t, "cluster", "cluster/apply-sidecar", func(t *testing.T) {
		dir := t.TempDir()
		src := copyFixture(t, filepath.Join(fixtures(t), "manifests", "simple-pod.yaml"), dir)

		_, _, code := runBin(t, "apply", "-f", src,
			"--skip-apply", "--sidecar", "--sidecar-skip-auto-sans",
			"--convert-secrets=false", "-n", evalNamespace,
		)
		if code != 0 {
			t.Fatalf("apply exited %d", code)
		}
		out, err := os.ReadFile(cocoOutput(src))
		if err != nil {
			t.Fatalf("output file missing: %v", err)
		}
		if !strings.Contains(string(out), "coco-secure-access") {
			t.Errorf("sidecar container 'coco-secure-access' not found in -coco.yaml:\n%s", out)
		}
	})

	check(t, "cluster", "cluster/apply-deployment", func(t *testing.T) {
		if out, err := exec.Command("kubectl", "get", "runtimeclass", evalRuntimeClass, "-o", "name").Output(); err != nil || !strings.Contains(string(out), evalRuntimeClass) {
			t.Skipf("%s RuntimeClass not found", evalRuntimeClass)
		}

		dir := t.TempDir()
		data, err := os.ReadFile(filepath.Join(fixtures(t), "manifests", "deployment.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		// Embed namespace so kubectl apply targets the eval namespace.
		patched := strings.Replace(string(data), "metadata:", "metadata:\n  namespace: "+evalNamespace, 1)
		src := filepath.Join(dir, "deployment.yaml")
		if err := os.WriteFile(src, []byte(patched), 0o644); err != nil {
			t.Fatal(err)
		}

		t.Cleanup(func() {
			exec.Command("kubectl", "delete", "deployment", "test-deployment",
				"-n", evalNamespace, "--ignore-not-found=true").Run() //nolint:errcheck
		})

		_, _, code := runBin(t, "apply", "-f", src,
			"--convert-secrets=false", "--runtime-class", evalRuntimeClass, "-n", evalNamespace,
		)
		if code != 0 {
			t.Fatalf("apply exited %d", code)
		}
		out, err := exec.Command("kubectl", "get", "deployment", "test-deployment",
			"-n", evalNamespace, "-o", "name").Output()
		if err != nil || !strings.Contains(string(out), "test-deployment") {
			t.Errorf("deployment not found after apply: err=%v, out=%s", err, out)
		}
		// Verify the transformation set runtimeClassName on the pod template spec.
		rcOut, err := exec.Command("kubectl", "get", "deployment", "test-deployment", "-n", evalNamespace,
			"-o", "jsonpath={.spec.template.spec.runtimeClassName}").Output()
		if err != nil || strings.TrimSpace(string(rcOut)) != evalRuntimeClass {
			t.Errorf("runtimeClassName not set on pod template: err=%v, got=%q, want=%q",
				err, strings.TrimSpace(string(rcOut)), evalRuntimeClass)
		}
	})
}

// createEvalNamespace creates evalNamespace (idempotent) and registers cleanup.
func createEvalNamespace(t *testing.T) {
	t.Helper()
	// Only delete the namespace on cleanup if this call actually created it.
	// If coco-eval already existed the eval must not destroy pre-existing resources.
	created := exec.Command("kubectl", "create", "namespace", evalNamespace).Run() == nil
	if !created {
		// Namespace already exists — verify it is reachable before proceeding.
		if out, err := exec.Command("kubectl", "get", "namespace", evalNamespace).CombinedOutput(); err != nil {
			t.Fatalf("namespace %s exists but is not accessible: %v\n%s", evalNamespace, err, out)
		}
	}
	if created {
		t.Cleanup(func() {
			exec.Command("kubectl", "delete", "namespace", evalNamespace,
				"--ignore-not-found=true", "--timeout=60s").Run() //nolint:errcheck
		})
	}
}

// backupCocoConfig saves ~/.kube/coco-config.toml and restores it on cleanup,
// so that kbs start does not permanently alter the developer's config.
func backupCocoConfig(t *testing.T) {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("UserHomeDir: %v", err)
	}
	cfgPath := filepath.Join(home, ".kube", "coco-config.toml")
	original, readErr := os.ReadFile(cfgPath)
	if readErr != nil && !os.IsNotExist(readErr) {
		// File exists but is unreadable — fail early rather than risk deleting it.
		t.Fatalf("config at %s exists but cannot be read: %v", cfgPath, readErr)
	}
	t.Cleanup(func() {
		if readErr == nil {
			os.WriteFile(cfgPath, original, 0o600) //nolint:errcheck
		} else {
			// File truly did not exist before; remove whatever the test wrote.
			os.Remove(cfgPath) //nolint:errcheck
		}
	})
}
