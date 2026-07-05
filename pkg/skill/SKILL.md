---
name: cocofy
description: Use when deploying or transforming a Kubernetes app for Confidential Containers (CoCo) with cococtl — CoCo-fying a manifest (RuntimeClass, sealed secrets, initdata), uploading secrets to Trustee KBS, or creating/validating initdata. Covers the init → apply → populate → deploy workflow and its ordering rules.
allowed-tools: Bash, Read
---

# CoCo-fy a Kubernetes app with cococtl

## Rule: use cococtl, not raw kubectl, for the transformation

Three transformations cannot be hand-crafted reliably, so never attempt them with raw
`kubectl` + yaml editing:

- **initdata** — 3 TOML files (aa.toml, cdh.toml, policy.rego) merged → gzip → base64 into one annotation.
- **sealed secrets** — `sealed.fakejwsheader.{base64url_json}.fakesignature` with embedded `kbs:///` URIs.
- **KBS upload** — authenticated HTTP API to Trustee using an Ed25519 admin key.

`kubectl` is used only for the final deploy and for verification. `cococtl` does everything else.

## Prerequisites (check first)

```bash
cococtl --version                      # binary installed (or: kubectl coco --version)
kubectl config current-context         # a reachable cluster with the CoCo runtime (kata-cc)
ls ~/.kube/coco-config.toml            # config exists (created by `cococtl init`)
```

If the config is missing, run `init` (next section). All commands work as `cococtl <cmd>` or
`kubectl coco <cmd>` — identical flags.

## The workflow

### 1. Initialize (once per cluster)

```bash
cococtl init
```

Deploys Trustee KBS to the current namespace, writes `~/.kube/coco-config.toml`, and saves the
KBS admin key to `~/.kube/coco-kbs-auth`. Use `--trustee-url <url>` to register an existing
Trustee instead of deploying one. Add `--enable-sidecar` only if the app needs the mTLS sidecar.

### 2. Transform the manifest (do NOT apply yet)

```bash
cococtl apply -f app.yaml --skip-apply
```

Produces two files next to the manifest:
- `app-coco.yaml` — the transformed manifest (RuntimeClass, sealed secret refs, initdata annotation).
- `app-trustee-secrets.yaml` — the secret values + KBS paths to upload. **Contains plaintext
  secrets — treat as sensitive, never commit.**

Preview without writing anything: `cococtl explain -f app.yaml` (educational, touches nothing).

Useful `apply` flags: `--runtime-class <name>` (default from config), `--init-container` (adds an
attestation-verify initContainer), `--convert-secrets=false` (skip secret handling),
`-n <namespace>`, `--sidecar`.

### 3. Upload secrets to KBS — before the workload starts

```bash
cococtl kbs populate -f app-trustee-secrets.yaml
```

This is mandatory ordering: **secrets must be in KBS before pods start**, or attestation-gated
secret retrieval fails at runtime. Other input modes: `--from-k8s-secret <name> -n <ns>`, or
`--path repository/type/tag --resource-file <file>` for a single resource.

### 4. Deploy

```bash
kubectl apply -f app-coco.yaml
```

> Running bare `cococtl apply -f app.yaml` (no `--skip-apply`) transforms AND `kubectl apply`s in
> one shot. Only safe when the required secrets are already in KBS. For first deploys, always use
> the `--skip-apply` → `populate` → `kubectl apply` sequence above.

## initdata: create, inspect, validate

initdata is generated automatically during `apply`. Handle it standalone when auditing or using
external tooling:

```bash
cococtl initdata create                          # → ~/.kube/coco-initdata.toml
cococtl initdata create --cacert /path/to/ca.crt # embed + validate a CA cert
cococtl initdata dump --raw                       # human-readable TOML
cococtl initdata dump                             # encoded blob (the annotation value)
cococtl initdata validate --file ~/.kube/coco-initdata.toml
cococtl initdata dump | cococtl initdata validate # validate the encoded blob
```

Validation checks: `version` = 0.1.0, `algorithm` in {sha256,sha384,sha512}, required `aa.toml`
+ `cdh.toml` present, and embedded certs are valid CA certs (rejects leaf/expired/SHA-1/short-RSA).
Always `validate` before trusting a hand-touched or externally-generated initdata.

## Verify the deploy

```bash
kubectl get pods                  # workload pods Running
kubectl describe pod <pod>        # confirm runtimeClassName: kata-cc and the cc_init_data annotation
kubectl logs <pod>                # app started; if --init-container, attestation check passed
```

## Gotchas that actually bite

- **Ordering**: secrets into KBS (`populate`) before the workload starts. First deploy = always
  `--skip-apply` then `populate` then `kubectl apply`.
- **Never hand-edit** the initdata blob, sealed secret strings, or `app-coco.yaml` annotations —
  regenerate with cococtl instead. Annotation placement (pod `metadata` vs `spec.template.metadata`)
  is handled automatically per resource kind.
- **Two namespaces**: the app namespace (from manifest / `-n` / context) is separate from the
  Trustee namespace (derived from `trustee_server` URL in config). Don't conflate them.
- **imagePullSecrets** stay in the manifest (CRI-O needs them) AND go to KBS — expected, not a bug.
- **`*-trustee-secrets.yaml` holds plaintext secrets** — delete or protect after `populate`; never commit.
- Config lives at `~/.kube/coco-config.toml`; override per-invocation with `--config <path>`.
