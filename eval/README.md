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
before running; both are restored on completion.

| Test | What it checks | Pass condition | Skip condition |
|------|---------------|----------------|----------------|
| `cluster/api-reachable` | Cluster connectivity | `kubectl cluster-info` exits 0 | — |
| `cluster/kbs-start` | `kubectl coco kbs start` | Trustee pod reaches `Ready` in `coco-eval` | — |
| `cluster/kbs-populate` | `kubectl coco kbs populate --path … --resource-file …` | Exit 0 | — |
| `cluster/apply-transforms-with-secrets` | `apply --skip-apply` with a real K8s secret | `-coco.yaml` contains `-sealed` secret ref; exit 0 | — |
| `cluster/apply-creates-pod` | `apply` (no `--skip-apply`) with `kata-qemu-coco-dev` | Pod object exists in `coco-eval` namespace | `kata-qemu-coco-dev` RuntimeClass absent |

### CoCo RuntimeClass (for `apply-creates-pod`)

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
