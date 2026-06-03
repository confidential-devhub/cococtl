# cococtl eval

Black-box evaluation of the `kubectl-coco` CLI binary against its expected
user-facing behaviour. Tests invoke the binary as a subprocess; none of them
call internal Go packages directly.

## Running

```bash
make eval-offline   # Tier 1 only — no cluster required
make eval           # Tier 1 + Tier 2 — requires a Kubernetes cluster
```

Set `COCOCTL_BINARY=/path/to/kubectl-coco` to test a binary other than the
one built in the repo root.

## Tier 1 — Offline

No cluster. Fixtures are copied from `integration_test/testdata/`.

| Test | What it checks | Pass condition |
|------|---------------|----------------|
| `explain/list-examples` | `--list-examples` flag | Exit 0; output contains `simple-pod` |
| `explain/example-text` | Built-in example, text format | Exit 0; output contains `kata-cc` |
| `explain/example-diff` | Built-in example, diff format | Exit 0 |
| `explain/example-markdown` | Built-in example, markdown format | Exit 0; output contains `#` |
| `explain/local-manifest` | `-f <file>` with a local YAML | Exit 0 |
| `apply/runtime-class` | `--skip-apply` on a simple Pod | `-coco.yaml` contains `runtimeClassName: kata-cc` |
| `apply/initdata-annotation` | `--skip-apply` on a simple Pod | `-coco.yaml` contains `cc_init_data` annotation |
| `apply/deployment-support` | `--skip-apply` on a Deployment | `-coco.yaml` contains `runtimeClassName: kata-cc` |
| `apply/secret-warning` | Pod with secrets, `--convert-secrets=false` | Warning about unconverted secrets in output |
| `apply/invalid-manifest-exits-nonzero` | Malformed YAML input | Non-zero exit |
| `apply/missing-file-exits-nonzero` | Non-existent input path | Non-zero exit |
| `initdata/create` | `initdata create --output <file>` | Exit 0; output file created |
| `initdata/dump-encoded` | `initdata dump` (default mode) | Exit 0; output is valid base64 |
| `initdata/dump-raw` | `initdata dump --raw` | Exit 0; output contains `"aa.toml"` key |
| `initdata/validate-valid` | `initdata validate` on generated TOML | Exit 0 |
| `initdata/validate-invalid-exits-nonzero` | `initdata validate` on invalid TOML | Non-zero exit |
| `completion/bash` | `completion bash` | Exit 0; non-empty output |
| `completion/zsh` | `completion zsh` | Exit 0; non-empty output |

## Tier 2 — Cluster

Requires a reachable Kubernetes cluster (`kubectl cluster-info` succeeds).
Drives the real user workflow end-to-end.

The eval creates a `coco-eval` namespace and backs up `~/.kube/coco-config.toml`
and `~/.kube/coco-sidecar/` before running; both are restored on completion.

| Test | What it checks | Pass condition | Skip condition |
|------|---------------|----------------|----------------|
| `cluster/api-reachable` | Cluster connectivity | `kubectl cluster-info` exits 0 | — |
| `cluster/init` | `kubectl coco init --enable-sidecar` (Day 1 command) | Config created with non-empty `trustee_server`; Trustee pod `Ready`; client CA generated | — |
| `cluster/kbs-start` | `kubectl coco kbs start` idempotency | Detects existing Trustee; exit 0 | — |
| `cluster/kbs-populate` | `kbs populate --path … --resource-file …` | Exit 0 | — |
| `cluster/kbs-content-verify` | Resource from `kbs-populate` is on disk in Trustee pod | `kubectl exec test -f <repo-path>` exits 0 (30 s timeout) | — |
| `cluster/kbs-populate-from-k8s-secret` | `kbs populate --from-k8s-secret` (alternate input mode) | Exit 0; file confirmed in KBS repo via `kubectl exec` | — |
| `cluster/apply-transforms-with-secrets` | `apply --skip-apply` with a real K8s secret; then `kbs populate -f` on generated trustee-secrets file | `-coco.yaml` has `-sealed` secret ref; secret value confirmed in KBS repo via `kubectl exec` | — |
| `cluster/apply-init-container` | `apply --init-container --skip-apply` | `-coco.yaml` contains `initContainers:` | — |
| `cluster/apply-creates-pod` | `apply` (no `--skip-apply`) with `kata-qemu-coco-dev` | Pod object exists in `coco-eval`; `spec.runtimeClassName` equals `kata-qemu-coco-dev` | `kata-qemu-coco-dev` RuntimeClass absent |
| `cluster/apply-sidecar` | `apply --sidecar --skip-apply` | `-coco.yaml` contains `coco-secure-access` container | — |
| `cluster/initdata-dump-validate-pipeline` | `initdata create → dump \| validate` pipe | `validate` reads encoded blob from stdin; exit 0 | — |
| `cluster/apply-deployment` | `apply` on a Deployment (not just Pod) | `test-deployment` object exists in `coco-eval`; `spec.template.spec.runtimeClassName` equals `kata-qemu-coco-dev` | `kata-qemu-coco-dev` RuntimeClass absent |

### CoCo RuntimeClass (for `apply-creates-pod` and `apply-deployment`)

Install with the official Helm chart:

```bash
helm install coco oci://ghcr.io/confidential-containers/charts/confidential-containers \
  --namespace coco-system --create-namespace --wait
```

Uninstall after the eval:

```bash
helm uninstall coco --namespace coco-system
kubectl delete namespace coco-system
```
