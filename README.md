# cococtl / kubectl-coco

A tool to deploy Confidential Containers (CoCo) applications on Kubernetes.

`cococtl` is designed primarily for developers to CoCo-fy their applications and test them with Trustee, the Remote Attestation Solution for CoCo. It's not meant for production deployment of CoCo applications.
Read more about CoCo at [confidentialcontainers.org](https://confidentialcontainers.org/).

## Usage Modes

The tool ships as a single binary (`cococtl`) and supports two invocation styles:

| Mode | Binary | Invocation |
|------|--------|------------|
| Standalone CLI | `cococtl` | `cococtl <command>` |
| kubectl plugin | `kubectl-coco` (symlink) | `kubectl coco <command>` |

All commands and flags are identical in both modes. The examples in this README use `cococtl`; replace with `kubectl coco` if you prefer the plugin style.

## Overview

`cococtl` simplifies the process of transforming regular Kubernetes manifests into CoCo-enabled manifests. It automatically handles:

- **RuntimeClass Configuration**: Sets the appropriate CoCo runtime
- **Secrets Management**: Converts K8s secrets to sealed secrets for upload to Trustee KBS via `kbs populate`
- **ImagePullSecrets**: Handles private registry credentials with automatic Trustee KBS integration
- **InitData Generation**: Creates aa.toml, cdh.toml, and policy.rego configurations


## Features

- ✅ **KBS Management**: Deploy in-cluster Trustee KBS or register an external instance; upload resources via `kbs populate`
- ✅ **Automatic Secret Conversion**: Detects and converts K8s secrets to sealed format; generates a trustee-secrets.yaml for upload via `kbs populate`
- ✅ **ImagePullSecrets Support**: Handles private registry credentials with Trustee KBS integration
- ✅ **Secure Access Sidecar**: Optional mTLS-secured sidecar for status reporting and secure port forwarding (see [sidecar/README.md](sidecar/README.md))
- ✅ **Multi-Resource Support**: Works with Pod, Deployment, StatefulSet, ReplicaSet, Job, DaemonSet
- ✅ **InitData Management**: Create, inspect, and validate initdata via the `initdata` subcommand; automatically generated during `apply`
- ✅ **Backup Management**: Saves transformed manifests with `-coco` suffix

> **Using an AI coding agent (e.g. Claude Code)?** cococtl embeds a `cocofy` skill that teaches agents the full init → apply → populate → deploy workflow. Install it into your agent's skills directory:
>
> ```bash
> mkdir -p ~/.claude/skills/cocofy
> cococtl skill > ~/.claude/skills/cocofy/SKILL.md
> ```

## Quick Start

### 1. Install

```bash
# Download latest release
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
if [ "$ARCH" = "x86_64" ]; then ARCH="amd64"; fi
curl -LO "https://github.com/confidential-devhub/cococtl/releases/latest/download/cococtl-${OS}-${ARCH}"

# Install standalone CLI
sudo install -m 0755 cococtl-${OS}-${ARCH} /usr/local/bin/cococtl

# Also install as kubectl plugin (optional)
sudo ln -sf /usr/local/bin/cococtl /usr/local/bin/kubectl-coco
sudo ln -sf /usr/local/bin/cococtl /usr/local/bin/kubectl_complete-coco

# Verify
cococtl --version
kubectl coco --version   # if kubectl plugin symlinks were created
```

See [Installation](#installation) for detailed options.

### 2. Initialize

Deploy Trustee and create configuration:

```bash
cococtl init
# or: kubectl coco init
```

This creates `~/.kube/coco-config.toml` and deploys Trustee to your cluster.

### 3. Transform

Use `--skip-apply` to generate the transformed manifest and secrets file without deploying yet:

```bash
cococtl apply -f your-app.yaml --skip-apply
# or: kubectl coco apply -f your-app.yaml --skip-apply
```

### 4. Upload Secrets to KBS

Secrets must be in KBS before the pods start:

```bash
cococtl kbs populate -f <app>-trustee-secrets.yaml
# or: kubectl coco kbs populate -f <app>-trustee-secrets.yaml
```

### 5. Deploy

```bash
kubectl apply -f your-app-coco.yaml
```

**Note:** There are some sample manifests under `examples` folder which you can try.

> `cococtl apply` runs `kubectl apply` automatically unless `--skip-apply` is set. Use `--skip-apply` when you need to upload secrets to KBS before the workload starts (recommended for first deployments).

## What Gets Transformed

`cococtl` performs these transformations:

1. **Sets RuntimeClass** to `kata-cc` (configurable)
2. **Converts Secrets**:
   - Detects all secret references (env, envFrom, volumes)
   - Creates sealed secrets with `-sealed` suffix
   - Writes KBS resource references to `<app>-trustee-secrets.yaml` (upload with `kbs populate`)
   - Updates manifest to use sealed secret names
3. **Handles ImagePullSecrets**:
   - Keeps imagePullSecrets in manifest (for CRI-O)
   - Writes credentials to `<app>-trustee-secrets.yaml` (upload with `kbs populate`)
   - Adds KBS URI to initdata CDH configuration
   - Falls back to default service account if not specified
4. **Generates InitData**: Creates aa.toml, cdh.toml, policy.rego
5. **Places Annotations**: Correctly adds initdata on pod templates
6. **Adds Custom Annotations**: From your config file

For detailed information, see [TRANSFORMATIONS.md](TRANSFORMATIONS.md).

## Prerequisites

- Go 1.24+ (for building from source)
- kubectl (for applying manifests)
- Kubernetes cluster with CoCo runtime installed

## Installation

### From Release Binary

1. **Download the latest release:**

   ```bash
   OS=$(uname -s | tr '[:upper:]' '[:lower:]')
   ARCH=$(uname -m)
   if [ "$ARCH" = "x86_64" ]; then ARCH="amd64"; fi
   curl -LO "https://github.com/confidential-devhub/cococtl/releases/latest/download/cococtl-${OS}-${ARCH}"
   ```

   For a specific version:
   ```bash
   VERSION=v0.1.0
   curl -LO "https://github.com/confidential-devhub/cococtl/releases/download/${VERSION}/cococtl-${OS}-${ARCH}"
   ```

2. **Validate (optional):**

   ```bash
   curl -LO "https://github.com/confidential-devhub/cococtl/releases/latest/download/cococtl-${OS}-${ARCH}.sha256"
   echo "$(cat cococtl-${OS}-${ARCH}.sha256)" | sha256sum --check
   ```

3. **Install:**

   System-wide (requires sudo):
   ```bash
   sudo install -m 0755 cococtl-${OS}-${ARCH} /usr/local/bin/cococtl

   # Optional: enable as kubectl plugin
   sudo ln -sf /usr/local/bin/cococtl /usr/local/bin/kubectl-coco
   sudo ln -sf /usr/local/bin/cococtl /usr/local/bin/kubectl_complete-coco
   ```

   Or user directory:
   ```bash
   mkdir -p ~/.local/bin
   install -m 0755 cococtl-${OS}-${ARCH} ~/.local/bin/cococtl
   export PATH=$PATH:~/.local/bin  # Add to ~/.bashrc or ~/.zshrc

   # Optional: enable as kubectl plugin
   ln -sf ~/.local/bin/cococtl ~/.local/bin/kubectl-coco
   ln -sf ~/.local/bin/cococtl ~/.local/bin/kubectl_complete-coco
   ```

4. **Verify:**

   ```bash
   cococtl --version
   kubectl coco --version   # if kubectl plugin symlinks were created
   ```

### From Source

```bash
git clone https://github.com/confidential-devhub/cococtl
cd cococtl
make build
sudo make install
```

`make install` installs the `cococtl` binary and automatically creates the `kubectl-coco` and `kubectl_complete-coco` symlinks in `$(INSTALL_PATH)` (default: `/usr/local/bin`).

## Shell Completion

cococtl supports tab completion for bash and zsh.

**How completion works — two independent mechanisms:**

| What you type | Driven by |
|---|---|
| `cococtl <TAB>` or `kubectl-coco <TAB>` | Generated completion script (source once) |
| `kubectl coco <TAB>` | kubectl calls `kubectl_complete-coco` directly; needs kubectl's own completion set up |

`make install` creates the `kubectl_complete-coco` symlink automatically. If you installed from a release binary, create it manually:
```bash
sudo ln -sf /usr/local/bin/cococtl /usr/local/bin/kubectl_complete-coco
```

### Bash

**Step 1 — Install bash-completion** (skip if already done):

```bash
# macOS
brew install bash-completion@2
echo '[[ -r "/opt/homebrew/etc/profile.d/bash_completion.sh" ]] && . "/opt/homebrew/etc/profile.d/bash_completion.sh"' >> ~/.bash_profile
source ~/.bash_profile

# Linux (Ubuntu/Debian)
apt-get install bash-completion

# Linux (CentOS/RHEL)
yum install bash-completion
```

**Step 2 — Install cococtl completion** (covers `cococtl` and `kubectl-coco`):

```bash
# Current session only
source <(cococtl completion bash)

# Permanent — macOS
cococtl completion bash > $(brew --prefix)/etc/bash_completion.d/cococtl

# Permanent — Linux, system-wide (requires root)
cococtl completion bash | sudo tee /etc/bash_completion.d/cococtl > /dev/null

# Permanent — Linux, current user only (no sudo)
mkdir -p ~/.local/share/bash-completion/completions
cococtl completion bash > ~/.local/share/bash-completion/completions/cococtl

# Then restart your shell
```

**Step 3 — Enable `kubectl coco <TAB>`** (if you use the kubectl plugin):

```bash
# macOS
kubectl completion bash > $(brew --prefix)/etc/bash_completion.d/kubectl

# Linux, system-wide (requires root)
kubectl completion bash | sudo tee /etc/bash_completion.d/kubectl > /dev/null

# Linux, current user only (no sudo)
kubectl completion bash > ~/.local/share/bash-completion/completions/kubectl
```

Verify the symlink is in PATH:
```bash
which kubectl_complete-coco   # should resolve to cococtl
```

### Zsh

**Step 1 — Enable compinit** (skip if already done):

```bash
echo "autoload -U compinit; compinit" >> ~/.zshrc
```

**Step 2 — Install cococtl completion** (covers `cococtl` and `kubectl-coco`):

```bash
cococtl completion zsh > "${fpath[1]}/_cococtl"
```

**Step 3 — Enable `kubectl coco <TAB>`** (if you use the kubectl plugin):

```bash
kubectl completion zsh > "${fpath[1]}/_kubectl"
```

Verify the symlink is in PATH, then start a new shell:
```bash
which kubectl_complete-coco   # should resolve to cococtl
exec zsh
```

## AI Agent Skill

cococtl embeds a `cocofy` skill for AI coding agents (e.g. Claude Code). It teaches the full
init → apply → populate → deploy workflow, the initdata create/validate commands, and the
ordering rules (secrets must reach KBS before pods start).

Print it to stdout and install it into your agent's skills directory:

```bash
mkdir -p ~/.claude/skills/cocofy
cococtl skill > ~/.claude/skills/cocofy/SKILL.md
```

The skill ships inside the binary, so it always matches your installed cococtl version — no
separate download needed.

## Usage

### Initialize Configuration

Deploy Trustee and create configuration (non-interactive by default):

```bash
cococtl init
# or: kubectl coco init
```

This deploys Trustee to your current namespace and creates `~/.kube/coco-config.toml`.

**Interactive mode:**

```bash
cococtl init --interactive  # or -i
```

**With custom Trustee:**

```bash
cococtl init --trustee-url https://trustee.example.com:8080
```

### Manage KBS (Key Broker Service)

The `kbs` subcommand manages the Trustee Key Broker Service that stores your secrets.

#### Deploy KBS in Kubernetes

```bash
cococtl kbs start --mode k8s
```

Deploys Trustee to the current namespace and saves the admin private key to `~/.kube/coco-kbs-auth`. The KBS URL is written to `~/.kube/coco-config.toml` for use by subsequent commands.

```bash
# With custom namespace
cococtl kbs start --mode k8s --namespace coco-system
```

#### Register an External KBS

```bash
cococtl kbs start --mode external --url http://kbs.example.com:8080
```

Records the KBS URL in config without deploying anything. Optionally specify `--auth-dir` to point at an existing admin key directory.

#### Upload Resources to KBS

After `cococtl apply` generates a `*-trustee-secrets.yaml`, upload the secrets:

```bash
cococtl kbs populate -f app-trustee-secrets.yaml
```

**Other input modes:**

```bash
# From a Kubernetes Secret
cococtl kbs populate --from-k8s-secret my-registry-secret -n my-namespace

# Single file to a specific KBS path
cococtl kbs populate --path default/myapp/password --resource-file /path/to/password.txt

# Direct URL (skips in-cluster port-forward)
cococtl kbs populate --kbs-url http://kbs.example.com:8080 --auth-key /path/to/private.key -f secrets.yaml
```

### Manage InitData

The `initdata` subcommand lets you create, inspect, and validate initdata independently of `apply`. This is useful for auditing initdata before deployment or generating it for use with external tooling.

#### Create initdata

Generate the raw initdata TOML from your config and save it to disk:

```bash
# From default config, save to ~/.kube/coco-initdata.toml
cococtl initdata create

# With a custom CA certificate (validates cert before embedding)
cococtl initdata create --cacert /path/to/ca.crt

# With a directory of CA certs
cococtl initdata create --capath /etc/ssl/certs

# Custom output path
cococtl initdata create --output /tmp/my-initdata.toml
```

#### Inspect initdata

```bash
# Show the base64+gzip encoded blob (ready for use as an annotation value)
cococtl initdata dump

# Show the human-readable plaintext TOML
cococtl initdata dump --raw

# Read from a specific file
cococtl initdata dump --file /tmp/my-initdata.toml
```

The default output of `dump` (without `--raw`) is the value to use for the
`io.katacontainers.config.hypervisor.cc_init_data` annotation.

#### Validate initdata

```bash
# Validate a saved TOML file (checks version, algorithm, required keys, embedded certs)
cococtl initdata validate --file ~/.kube/coco-initdata.toml

# Validate the encoded blob from dump via pipe
cococtl initdata dump | cococtl initdata validate
```

Validation checks:
- `version` is `0.1.0` and `algorithm` is one of `sha256`, `sha384`, `sha512`
- Required keys `aa.toml` and `cdh.toml` are present (`policy.rego` is optional)
- Embedded certificates must be CA certificates (`CA:TRUE`, `keyCertSign`); rejected: leaf/non-CA certs, expired or not-yet-valid certs, SHA-1 or MD5 signatures, unknown critical extensions, RSA keys shorter than 1024 bits
- All `aa.toml` token config URLs are consistent with `cdh.toml` kbc URL (a warning is printed if any differ)

### Transform and Apply Manifests

**Basic usage:**

```bash
cococtl apply -f app.yaml
```

**Common options:**
```bash
# Only transform, don't apply
cococtl apply -f app.yaml --skip-apply

# Use specific runtime class
cococtl apply -f app.yaml --runtime-class kata-remote

# Add attestation initContainer
cococtl apply -f app.yaml --init-container

# Enable secure access sidecar
cococtl apply -f app.yaml --sidecar

# Disable automatic secret conversion
cococtl apply -f app.yaml --convert-secrets=false

# Use custom config file
cococtl apply -f app.yaml --config /path/to/config.toml
```

See [TRANSFORMATIONS.md](TRANSFORMATIONS.md) for detailed description on the transformations.

### Learn CoCo Transformations

The `explain` command helps you understand what transformations are applied to your manifests:

```bash
# Analyze your manifest
cococtl explain -f your-app.yaml

# View built-in examples
cococtl explain --list-examples

# Learn with interactive examples
cococtl explain --example simple-pod
cococtl explain --example deployment-secrets
cococtl explain --example sidecar-service
```

**Output formats:**
```bash
# Human-readable (default)
cococtl explain -f app.yaml

# Side-by-side diff view
cococtl explain -f app.yaml --format diff

# Markdown for documentation
cococtl explain -f app.yaml --format markdown -o transformations.md
```

The explain command provides:
- **Educational analysis** of each transformation
- **Before/after comparisons** for secrets, runtime, and initdata
- **Learning points** explaining why each change is needed
- **Interactive examples** to explore CoCo concepts

Perfect for learning how CoCo works without making any changes to your cluster.

### Secure Access Sidecar

The secure access sidecar provides mTLS-secured HTTPS access to your CoCo pods.

**One-time setup:**

```bash
cococtl init --enable-sidecar
```

**Deploy with sidecar:**

```bash
# Basic usage
cococtl apply -f app.yaml --sidecar

# Enable port forwarding from primary container
cococtl apply -f app.yaml --sidecar --sidecar-port-forward 8888

# Custom SANs for LoadBalancer or Ingress
cococtl apply -f app.yaml --sidecar \
  --sidecar-san-ips=203.0.113.10 \
  --sidecar-san-dns=myapp.example.com
```

**Note:** When `--sidecar` is enabled, a Kubernetes Service (ClusterIP type) is automatically created with the name `<app-name>-sidecar` to expose the sidecar's HTTPS port. You can convert it to NodePort or use it with an Ingress for external access.

See [sidecar/README.md](sidecar/README.md) for detailed configuration and usage.

## Configuration File

The configuration file (`~/.kube/coco-config.toml`) supports:

```toml
# Mandatory
trustee_server = 'https://trustee-kbs.default.svc.cluster.local:8080'
runtime_class = 'kata-cc'

# Optional
trustee_ca_cert = '/path/to/ca.crt'
kata_agent_policy = '/path/to/policy.rego'
init_container_image = 'quay.io/fedora/fedora:44'
init_container_cmd = 'curl http://localhost:8006/cdh/resource/default/attestation-status/status'

# Image-related (optional, for CDH [image] section)
container_policy_uri = 'kbs:///default/security-policy/test'
registry_cred_uri = 'kbs:///default/credential/test'
registry_config_uri = 'kbs:///default/registry-configuration/test'

# Custom annotations (optional, only non-empty values applied)
[annotations]
"io.katacontainers.config.runtime.create_container_timeout" = "120"
"io.katacontainers.config.hypervisor.machine_type" = "q35"

# Secure access sidecar (optional)
[sidecar]
enabled = true
image = "ghcr.io/confidential-devhub/coco-sidecar:latest"  # Optional: custom sidecar image
https_port = 8443                                          # Optional: HTTPS port (default: 8443)
forward_port = 8888                                        # Optional: application port to forward
cpu_limit = "100m"                                         # Optional: CPU limit
memory_limit = "128Mi"                                     # Optional: memory limit
cpu_request = "50m"                                        # Optional: CPU request
memory_request = "64Mi"                                    # Optional: memory request
```

**Note:** TLS certificates are auto-generated per-app during `cococtl apply --sidecar`.

## Development

### Building

```bash
make build
```

### Testing

```bash
make test
```

### Cleaning

```bash
make clean
```

## References

- [Confidential Containers Documentation](https://confidentialcontainers.org/)
- [InitData Feature](https://confidentialcontainers.org/docs/features/initdata/)
- [Sealed Secrets](https://confidentialcontainers.org/docs/features/sealed-secrets/)
- [Trustee Remote Attestation](https://github.com/confidential-containers/trustee)

## License

Apache License 2.0

## Contributing

Contributions are welcome! Please submit issues and pull requests to the [repository](https://github.com/confidential-devhub/cococtl).
