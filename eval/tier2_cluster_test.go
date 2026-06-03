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
	// Config and sidecar certs are written by init; restore originals on cleanup.
	backupCocoConfig(t)
	backupCertDir(t)

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
		stdout, stderr, code := runBin(t, "init",
			"--trustee-namespace", evalNamespace,
			"--enable-sidecar",
		)
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

	check(t, "cluster", "cluster/kata-pod-running", func(t *testing.T) {
		if out, err := exec.Command("kubectl", "get", "runtimeclass", evalRuntimeClass, "-o", "name").Output(); err != nil || !strings.Contains(string(out), evalRuntimeClass) {
			t.Skipf("%s RuntimeClass not found", evalRuntimeClass)
		}

		const podName = "coco-eval-kata-running"
		dir := t.TempDir()
		podFile := filepath.Join(dir, "kata-running.yaml")
		// Use quay.io so CDH inside the kata VM can pull without Docker Hub
		// rate limits; kubectl:latest is already cached on the node from kata CI.
		if err := os.WriteFile(podFile, []byte(`apiVersion: v1
kind: Pod
metadata:
  name: `+podName+`
  namespace: `+evalNamespace+`
spec:
  containers:
  - name: app
    image: quay.io/kata-containers/kubectl:latest
    imagePullPolicy: IfNotPresent
    command: ["/bin/sh", "-c", "sleep 3600"]
`), 0o644); err != nil {
			t.Fatal(err)
		}

		t.Cleanup(func() {
			exec.Command("kubectl", "delete", "pod", podName, "-n", evalNamespace,
				"--ignore-not-found=true", "--timeout=30s").Run() //nolint:errcheck
		})

		// cococtl apply adds cc_init_data, runtimeClassName and transforms the manifest.
		stdout, stderr, code := runBin(t, "apply", "-f", podFile,
			"--convert-secrets=false", "--runtime-class", evalRuntimeClass, "-n", evalNamespace,
		)
		if code != 0 {
			t.Fatalf("apply exited %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
		}

		// kata VM startup is slower than runc — allow up to 5 minutes.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		if out, err := exec.CommandContext(ctx, "kubectl", "wait",
			"--for=condition=ready", "pod", podName,
			"-n", evalNamespace, "--timeout=300s",
		).CombinedOutput(); err != nil {
			// Capture pod events for diagnostics before failing.
			events, _ := exec.Command("kubectl", "describe", "pod", podName, "-n", evalNamespace).Output()
			t.Fatalf("pod did not reach Ready: %v\n%s\n--- describe ---\n%s", err, out, events)
		}

		// Verify the container state is Running (not CrashLoopBackOff or Waiting).
		stateCtx, stateCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer stateCancel()
		stateOut, err := exec.CommandContext(stateCtx, "kubectl", "get", "pod", podName,
			"-n", evalNamespace,
			"-o", "jsonpath={.status.containerStatuses[0].state.running}",
		).Output()
		if err != nil || strings.TrimSpace(string(stateOut)) == "" {
			t.Errorf("kata container is not in running state: err=%v, state=%q", err, string(stateOut))
		}
	})

	check(t, "cluster", "cluster/apply-sidecar", func(t *testing.T) {
		dir := t.TempDir()
		src := copyFixture(t, filepath.Join(fixtures(t), "manifests", "simple-pod.yaml"), dir)

		const sidecarImage = "quay.io/confidential-devhub/coco-secure-access:latest"
		stdout, stderr, code := runBin(t, "apply", "-f", src,
			"--skip-apply", "--sidecar",
			"--sidecar-image", sidecarImage,
			"--sidecar-skip-auto-sans",
			"--sidecar-san-dns", "eval-app."+evalNamespace+".svc.cluster.local",
			"--convert-secrets=false", "-n", evalNamespace,
		)
		if code != 0 {
			t.Fatalf("apply exited %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
		}
		out, err := os.ReadFile(cocoOutput(src))
		if err != nil {
			t.Fatalf("output file missing: %v", err)
		}
		if !strings.Contains(string(out), "coco-secure-access") {
			t.Errorf("sidecar container 'coco-secure-access' not found in -coco.yaml:\n%s", out)
		}
	})

	check(t, "cluster", "cluster/initdata-dump-validate-pipeline", func(t *testing.T) {
		dir := t.TempDir()
		tomlFile := filepath.Join(dir, "initdata.toml")

		// Create initdata from the config written by init/kbs-start (real KBS URL).
		if _, _, code := runBin(t, "initdata", "create", "--output", tomlFile); code != 0 {
			t.Fatalf("initdata create exited %d", code)
		}

		// Capture dump output and feed it to validate via stdin.
		dumpOut, _, code := runBin(t, "initdata", "dump", "--file", tomlFile)
		if code != 0 {
			t.Fatalf("initdata dump exited %d", code)
		}

		cmd := exec.Command(binary(t), "initdata", "validate")
		cmd.Stdin = strings.NewReader(dumpOut)
		var outBuf, errBuf strings.Builder
		cmd.Stdout = &outBuf
		cmd.Stderr = &errBuf
		if err := cmd.Run(); err != nil {
			t.Fatalf("initdata validate exited non-zero\nstdout: %s\nstderr: %s",
				outBuf.String(), errBuf.String())
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

	check(t, "cluster", "cluster/apply-volume-secret", func(t *testing.T) {
		// Create a K8s secret that will be mounted as a volume.
		genOut, err := exec.Command("kubectl", "create", "secret", "generic", "eval-vol-secret",
			"--from-literal=config.yaml=key: value",
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

		// Write pod manifest with a volume secret reference (different code path
		// from env secretKeyRef — detected via volumes[].secret.secretName).
		dir := t.TempDir()
		podFile := filepath.Join(dir, "vol-pod.yaml")
		if err := os.WriteFile(podFile, []byte(`apiVersion: v1
kind: Pod
metadata:
  name: eval-vol-secret-pod
  namespace: `+evalNamespace+`
spec:
  containers:
  - name: app
    image: quay.io/kata-containers/kubectl:latest
    imagePullPolicy: IfNotPresent
    volumeMounts:
    - name: cfg
      mountPath: /etc/config
  volumes:
  - name: cfg
    secret:
      secretName: eval-vol-secret
`), 0o644); err != nil {
			t.Fatal(err)
		}

		stdout, stderr, code := runBin(t, "apply", "-f", podFile,
			"--skip-apply", "-n", evalNamespace,
		)
		if code != 0 {
			t.Fatalf("apply exited %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
		}

		// Volume secretName should be renamed with -sealed suffix.
		coco, err := os.ReadFile(cocoOutput(podFile))
		if err != nil {
			t.Fatalf("output file missing: %v", err)
		}
		if !strings.Contains(string(coco), "eval-vol-secret-sealed") {
			t.Errorf("sealed volume secret not found in -coco.yaml:\n%s", coco)
		}

		// Upload the generated trustee-secrets file to KBS.
		trusteeSecrets := strings.TrimSuffix(podFile, ".yaml") + "-trustee-secrets.yaml"
		if _, err := os.Stat(trusteeSecrets); err != nil {
			t.Fatalf("trustee-secrets file not generated: %v", err)
		}
		if stdout, stderr, code = runBin(t, "kbs", "populate",
			"-f", trusteeSecrets, "--namespace", evalNamespace,
		); code != 0 {
			t.Fatalf("kbs populate exited %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
		}

		// Confirm the secret key landed in the KBS repository on disk.
		const repoBase = "/opt/confidential-containers/kbs/repository"
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if out, err := exec.CommandContext(ctx, "kubectl", "exec",
			"-n", evalNamespace, "deployment/trustee-deployment", "--",
			"test", "-f", repoBase+"/"+evalNamespace+"/eval-vol-secret/config.yaml",
		).CombinedOutput(); err != nil {
			t.Fatalf("volume secret not found in KBS repository: %v\n%s", err, out)
		}
	})

	check(t, "cluster", "cluster/apply-multidoc", func(t *testing.T) {
		dir := t.TempDir()
		src := filepath.Join(dir, "pod-with-service.yaml")

		// Multi-document YAML: Pod (primary workload) + Service (secondary).
		// Namespace embedded so kubectl apply targets coco-eval.
		if err := os.WriteFile(src, []byte(`apiVersion: v1
kind: Pod
metadata:
  name: eval-multidoc-pod
  namespace: `+evalNamespace+`
  labels:
    app: eval-multidoc
spec:
  containers:
  - name: app
    image: quay.io/kata-containers/kubectl:latest
    imagePullPolicy: IfNotPresent
    ports:
    - containerPort: 8080
---
apiVersion: v1
kind: Service
metadata:
  name: eval-multidoc-svc
  namespace: `+evalNamespace+`
spec:
  selector:
    app: eval-multidoc
  ports:
  - port: 80
    targetPort: 8080
`), 0o644); err != nil {
			t.Fatal(err)
		}

		t.Cleanup(func() {
			exec.Command("kubectl", "delete", "pod", "eval-multidoc-pod",
				"-n", evalNamespace, "--ignore-not-found=true").Run() //nolint:errcheck
			exec.Command("kubectl", "delete", "svc", "eval-multidoc-svc",
				"-n", evalNamespace, "--ignore-not-found=true").Run() //nolint:errcheck
		})

		// Transformation check (always runs): the primary workload gets cc_init_data;
		// the Service document is extracted but NOT included in -coco.yaml.
		stdout, stderr, code := runBin(t, "apply", "-f", src,
			"--skip-apply", "--convert-secrets=false", "-n", evalNamespace,
		)
		if code != 0 {
			t.Fatalf("apply exited %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
		}
		coco, err := os.ReadFile(cocoOutput(src))
		if err != nil {
			t.Fatalf("-coco.yaml missing: %v", err)
		}
		if !strings.Contains(string(coco), "cc_init_data") {
			t.Errorf("cc_init_data annotation not found in -coco.yaml")
		}
		// cococtl applies only the primary workload; the Service document is
		// not written to -coco.yaml, ensuring the annotation is never placed on it.
		if strings.Contains(string(coco), "kind: Service") {
			t.Errorf("Service document unexpectedly included in -coco.yaml:\n%s", coco)
		}

		// Cluster apply check (skipped without kata RuntimeClass).
		if out, err := exec.Command("kubectl", "get", "runtimeclass", evalRuntimeClass, "-o", "name").Output(); err != nil || !strings.Contains(string(out), evalRuntimeClass) {
			t.Skipf("%s RuntimeClass not found — skipping cluster apply check", evalRuntimeClass)
		}
		_, _, code = runBin(t, "apply", "-f", src,
			"--convert-secrets=false", "--runtime-class", evalRuntimeClass, "-n", evalNamespace,
		)
		if code != 0 {
			t.Fatalf("cluster apply exited %d", code)
		}
		// Primary workload (Pod) must exist.
		if out, err := exec.Command("kubectl", "get", "pod", "eval-multidoc-pod",
			"-n", evalNamespace, "-o", "name").Output(); err != nil || !strings.Contains(string(out), "eval-multidoc-pod") {
			t.Errorf("Pod not found after apply: err=%v, out=%s", err, out)
		}
		// Service must NOT exist — cococtl applies only the primary workload.
		// Check err too: a kubectl failure (empty output) must not silently pass.
		if out, err := exec.Command("kubectl", "get", "svc", "eval-multidoc-svc",
			"-n", evalNamespace, "--ignore-not-found").Output(); err != nil || strings.Contains(string(out), "eval-multidoc-svc") {
			t.Errorf("Service unexpectedly created by cococtl apply (err=%v): %s", err, out)
		}
	})

	check(t, "cluster", "cluster/apply-reapply-idempotency", func(t *testing.T) {
		// Create a secret the pod will reference.
		genOut, err := exec.Command("kubectl", "create", "secret", "generic", "eval-idempotent-secret",
			"--from-literal=key=value", "-n", evalNamespace, "--dry-run=client", "-o", "yaml",
		).Output()
		if err != nil {
			t.Fatalf("generate secret YAML: %v", err)
		}
		ap := exec.Command("kubectl", "apply", "-f", "-")
		ap.Stdin = strings.NewReader(string(genOut))
		if out, err := ap.CombinedOutput(); err != nil {
			t.Fatalf("kubectl apply secret: %v\n%s", err, out)
		}

		dir := t.TempDir()
		podFile := filepath.Join(dir, "pod.yaml")
		if err := os.WriteFile(podFile, []byte(`apiVersion: v1
kind: Pod
metadata:
  name: eval-idempotent-pod
  namespace: `+evalNamespace+`
spec:
  containers:
  - name: app
    image: quay.io/kata-containers/kubectl:latest
    imagePullPolicy: IfNotPresent
    env:
    - name: KEY
      valueFrom:
        secretKeyRef:
          name: eval-idempotent-secret
          key: key
`), 0o644); err != nil {
			t.Fatal(err)
		}

		// Run 1: --skip-apply with secret conversion.
		s1, e1, c1 := runBin(t, "apply", "-f", podFile, "--skip-apply", "-n", evalNamespace)
		if c1 != 0 {
			t.Fatalf("run 1 exited %d\nstdout: %s\nstderr: %s", c1, s1, e1)
		}
		coco1, err := os.ReadFile(cocoOutput(podFile))
		if err != nil {
			t.Fatalf("run 1 -coco.yaml missing: %v", err)
		}

		// Run 2: identical command — must also exit 0 with the same output.
		s2, e2, c2 := runBin(t, "apply", "-f", podFile, "--skip-apply", "-n", evalNamespace)
		if c2 != 0 {
			t.Fatalf("run 2 (re-apply) exited %d\nstdout: %s\nstderr: %s", c2, s2, e2)
		}
		coco2, err := os.ReadFile(cocoOutput(podFile))
		if err != nil {
			t.Fatalf("run 2 -coco.yaml missing: %v", err)
		}
		if string(coco1) != string(coco2) {
			t.Errorf("re-apply produced different -coco.yaml:\nrun1:\n%s\nrun2:\n%s", coco1, coco2)
		}

		// Full cluster apply (skip if kata not available).
		if out, err := exec.Command("kubectl", "get", "runtimeclass", evalRuntimeClass, "-o", "name").Output(); err != nil || !strings.Contains(string(out), evalRuntimeClass) {
			t.Skipf("%s not found — skipping cluster re-apply check", evalRuntimeClass)
		}
		t.Cleanup(func() {
			exec.Command("kubectl", "delete", "pod", "eval-idempotent-pod",
				"-n", evalNamespace, "--ignore-not-found=true").Run() //nolint:errcheck
		})
		for run := 1; run <= 2; run++ {
			if _, _, code := runBin(t, "apply", "-f", podFile,
				"--runtime-class", evalRuntimeClass, "-n", evalNamespace,
			); code != 0 {
				t.Fatalf("cluster apply run %d exited %d", run, code)
			}
		}
		if out, err := exec.Command("kubectl", "get", "pod", "eval-idempotent-pod",
			"-n", evalNamespace, "-o", "name").Output(); err != nil || !strings.Contains(string(out), "eval-idempotent-pod") {
			t.Errorf("pod not found after re-apply: err=%v, out=%s", err, out)
		}
	})

	check(t, "cluster", "cluster/apply-statefulset", func(t *testing.T) {
		dir := t.TempDir()
		src := filepath.Join(dir, "sts.yaml")
		if err := os.WriteFile(src, []byte(`apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: eval-sts
  namespace: `+evalNamespace+`
spec:
  serviceName: eval-sts
  replicas: 1
  selector:
    matchLabels:
      app: eval-sts
  template:
    metadata:
      labels:
        app: eval-sts
    spec:
      containers:
      - name: app
        image: quay.io/kata-containers/kubectl:latest
        imagePullPolicy: IfNotPresent
        command: ["/bin/sh", "-c", "sleep 3600"]
`), 0o644); err != nil {
			t.Fatal(err)
		}

		// Transformation check: cc_init_data must be on spec.template, NOT top-level metadata.
		stdout, stderr, code := runBin(t, "apply", "-f", src,
			"--skip-apply", "--convert-secrets=false", "-n", evalNamespace,
		)
		if code != 0 {
			t.Fatalf("apply exited %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
		}
		coco, err := os.ReadFile(cocoOutput(src))
		if err != nil {
			t.Fatalf("-coco.yaml missing: %v", err)
		}
		cocoStr := string(coco)
		if !strings.Contains(cocoStr, "cc_init_data") {
			t.Errorf("cc_init_data annotation not found in -coco.yaml")
		}
		// The annotation must appear inside the template section, not in the
		// top-level StatefulSet metadata (the critical workload-resource invariant).
		parts := strings.SplitN(cocoStr, "  template:", 2)
		if len(parts) < 2 {
			t.Fatalf("template: section not found in -coco.yaml")
		}
		if strings.Contains(parts[0], "cc_init_data") {
			t.Errorf("cc_init_data found in top-level metadata instead of spec.template.metadata")
		}
		if !strings.Contains(parts[1], "cc_init_data") {
			t.Errorf("cc_init_data not found inside spec.template in -coco.yaml")
		}

		// Cluster apply check (skipped without kata RuntimeClass).
		if out, err := exec.Command("kubectl", "get", "runtimeclass", evalRuntimeClass, "-o", "name").Output(); err != nil || !strings.Contains(string(out), evalRuntimeClass) {
			t.Skipf("%s RuntimeClass not found — skipping cluster apply check", evalRuntimeClass)
		}
		t.Cleanup(func() {
			exec.Command("kubectl", "delete", "statefulset", "eval-sts",
				"-n", evalNamespace, "--ignore-not-found=true").Run() //nolint:errcheck
		})
		_, _, code = runBin(t, "apply", "-f", src,
			"--convert-secrets=false", "--runtime-class", evalRuntimeClass, "-n", evalNamespace,
		)
		if code != 0 {
			t.Fatalf("cluster apply exited %d", code)
		}
		out, err := exec.Command("kubectl", "get", "statefulset", "eval-sts",
			"-n", evalNamespace, "-o", "name").Output()
		if err != nil || !strings.Contains(string(out), "eval-sts") {
			t.Errorf("StatefulSet not found after apply: err=%v, out=%s", err, out)
		}
		// Annotation must be on the pod template in the cluster object too.
		rcOut, err := exec.Command("kubectl", "get", "statefulset", "eval-sts",
			"-n", evalNamespace,
			"-o", "jsonpath={.spec.template.spec.runtimeClassName}").Output()
		if err != nil || strings.TrimSpace(string(rcOut)) != evalRuntimeClass {
			t.Errorf("runtimeClassName not set on pod template: err=%v, got=%q", err, string(rcOut))
		}
	})

	check(t, "cluster", "cluster/kbs-start-external", func(t *testing.T) {
		// Register a pre-existing external KBS without touching the cluster.
		const externalURL = "http://kbs.external.example.com:8080"

		// Snapshot deployments (stable objects) before the command.
		// Using deployments rather than pods avoids flakiness from Terminating
		// pods left by prior test cleanups.
		depsBefore, err := exec.Command("kubectl", "get", "deployments",
			"-n", evalNamespace, "-o", "name").Output()
		if err != nil {
			t.Fatalf("kubectl get deployments: %v", err)
		}

		stdout, stderr, code := runBin(t, "kbs", "start",
			"--mode", "external",
			"--url", externalURL,
		)
		if code != 0 {
			t.Fatalf("kbs start --mode external exited %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
		}

		// Config must contain the registered URL.
		home, _ := os.UserHomeDir()
		cfgData, err := os.ReadFile(filepath.Join(home, ".kube", "coco-config.toml"))
		if err != nil {
			t.Fatalf("config not readable: %v", err)
		}
		if !strings.Contains(string(cfgData), externalURL) {
			t.Errorf("config does not contain registered URL %q:\n%s", externalURL, cfgData)
		}

		// No new Trustee deployment — deployment names must be unchanged.
		depsAfter, err := exec.Command("kubectl", "get", "deployments",
			"-n", evalNamespace, "-o", "name").Output()
		if err != nil {
			t.Fatalf("kubectl get deployments: %v", err)
		}
		if string(depsBefore) != string(depsAfter) {
			t.Errorf("deployments changed after kbs start --mode external (expected no cluster interaction):\nbefore: %s\nafter:  %s",
				depsBefore, depsAfter)
		}
	})

	check(t, "cluster", "cluster/init-skip-trustee-deploy", func(t *testing.T) {
		// Simulate the "I already have a KBS" flow: init with an explicit URL
		// and --skip-trustee-deploy so no new Trustee pod is created.
		kbsURL := "http://trustee-kbs." + evalNamespace + ".svc.cluster.local:8080"

		// Snapshot deployments (stable objects) before the command.
		depsBefore, err := exec.Command("kubectl", "get", "deployments",
			"-n", evalNamespace, "-o", "name").Output()
		if err != nil {
			t.Fatalf("kubectl get deployments: %v", err)
		}

		stdout, stderr, code := runBin(t, "init",
			"--skip-trustee-deploy",
			"--trustee-url", kbsURL,
		)
		if code != 0 {
			t.Fatalf("init exited %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
		}

		// Config must contain the explicitly provided KBS URL.
		home, _ := os.UserHomeDir()
		cfgData, err := os.ReadFile(filepath.Join(home, ".kube", "coco-config.toml"))
		if err != nil {
			t.Fatalf("config not readable: %v", err)
		}
		if !strings.Contains(string(cfgData), kbsURL) {
			t.Errorf("config does not contain expected URL %q:\n%s", kbsURL, cfgData)
		}

		// No new Trustee deployment — deployment names must be unchanged.
		depsAfter, err := exec.Command("kubectl", "get", "deployments",
			"-n", evalNamespace, "-o", "name").Output()
		if err != nil {
			t.Fatalf("kubectl get deployments: %v", err)
		}
		if string(depsBefore) != string(depsAfter) {
			t.Errorf("deployments changed after init --skip-trustee-deploy (expected no deployment):\nbefore: %s\nafter:  %s",
				depsBefore, depsAfter)
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

// backupCertDir copies ~/.kube/coco-sidecar/ to a temp location and restores
// it on cleanup, so that init --enable-sidecar does not permanently alter the
// developer's sidecar certificates.
func backupCertDir(t *testing.T) {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("UserHomeDir: %v", err)
	}
	certDir := filepath.Join(home, ".kube", "coco-sidecar")

	// Snapshot existing contents before any test writes.
	snapshot, snapshotErr := snapshotDir(certDir)

	t.Cleanup(func() {
		if snapshotErr != nil {
			// Snapshot failed — preserve the original directory to avoid data loss.
			return
		}
		os.RemoveAll(certDir) //nolint:errcheck
		if len(snapshot) > 0 {
			restoreDir(certDir, snapshot)
		}
	})
}

// snapshotDir reads all files in dir into a map[relpath]contents.
// Returns nil map (not an error) when dir does not exist.
func snapshotDir(dir string) (map[string][]byte, error) {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return map[string][]byte{}, nil
	}
	snap := map[string][]byte{}
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(dir, path)
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		snap[rel] = data
		return nil
	})
	return snap, err
}

// restoreDir writes a snapshotDir snapshot back to dir.
func restoreDir(dir string, snap map[string][]byte) {
	for rel, data := range snap {
		dst := filepath.Join(dir, rel)
		_ = os.MkdirAll(filepath.Dir(dst), 0o700)
		_ = os.WriteFile(dst, data, 0o600)
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
