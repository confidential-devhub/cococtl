# kubectl-coco

A kubectl plugin to deploy Confidential Containers (CoCo) applications.

## Overview

`kubectl-coco` simplifies the process of transforming regular Kubernetes manifests into CoCo-enabled manifests. It automatically handles:

- RuntimeClass configuration
- InitData generation (aa.toml, cdh.toml, policy.rego)
- Sealed secret conversion
- Manifest transformation and backup

## Features

- **Interactive Configuration**: Initialize CoCo configuration and infrastructure with `init` command
- **Automatic Transformation**: Convert regular K8s manifests to CoCo-enabled manifests
- **Sealed Secrets**: Generate sealed secrets using coco-tools
- **InitData Generation**: Automatically generate initdata with proper compression and encoding
- **Backup Management**: Save original manifests with `-coco` suffix
- **kubectl Integration**: Seamlessly apply transformed manifests

## Prerequisites

- Go 1.24 or later (for building from source)
- kubectl (for applying manifests)

## Installation

### Install kubectl-coco release

1. Download the latest release:

   ```bash
   OS=$(uname -s | tr '[:upper:]' '[:lower:]')
   ARCH=$(uname -m)
   if [ "$ARCH" = "x86_64" ]; then ARCH="amd64"; fi
   curl -LO "https://github.com/confidential-devhub/cococtl/releases/latest/download/kubectl-coco-${OS}-${ARCH}"
   ```

   > **Note:** To download a specific version, replace `latest` with the specific version tag.
   >
   > For example, to download version `v0.1.0`:
   > ```bash
   > VERSION=v0.1.0
   > curl -LO "https://github.com/confidential-devhub/cococtl/releases/download/${VERSION}/kubectl-coco-${OS}-${ARCH}"
   > ```

1. Validate the binary (optional):

   Download the checksum file:

   ```bash
   curl -LO "https://github.com/confidential-devhub/cococtl/releases/latest/download/kubectl-coco-${OS}-${ARCH}.sha256"
   ```

   Validate the kubectl-coco binary against the checksum file:

   ```bash
   echo "$(cat kubectl-coco-${OS}-${ARCH}.sha256)" | sha256sum --check
   ```

   If valid, the output should be:

   ```
   kubectl-coco-<OS>-<ARCH>: OK
   ```

1. Install kubectl-coco:

   **Option 1: Install to system path (requires sudo)**

   ```bash
   sudo install -m 0755 kubectl-coco-${OS}-${ARCH} /usr/local/bin/kubectl-coco
   ```

   **Option 2: Install to user directory**

   ```bash
   mkdir -p ~/.local/bin
   install -m 0755 kubectl-coco-${OS}-${ARCH} ~/.local/bin/kubectl-coco
   ```

   Then ensure `~/.local/bin` is in your PATH:

   ```bash
   export PATH=$PATH:~/.local/bin
   ```

   Add this to your `~/.bashrc` or `~/.zshrc` to make it permanent.

1. Test to ensure the version you installed is up-to-date:

   ```bash
   kubectl coco --version
   ```

1. Clean up the installation files:

   ```bash
   rm kubectl-coco-${OS}-${ARCH} kubectl-coco-${OS}-${ARCH}.sha256
   ```

### Install from Source

```bash
git clone https://github.com/confidential-devhub/cococtl
cd cococtl
make build
sudo make install
```

### Manual Build and Installation

```bash
go build -o kubectl-coco .
sudo mv kubectl-coco /usr/local/bin/
```

## Usage

### 1. Initialize Configuration

First, initialize CoCo configuration:

```bash
kubectl coco init
```

This creates `~/.kube/coco-config.toml` with the following settings:

```toml
# Trustee server URL (mandatory)
trustee_server = 'https://your-trustee-server:8080'

# Default RuntimeClass to use when --runtime-class is not specified
runtime_class = 'kata-cc'

# Optional settings
trustee_ca_cert = '/path/to/ca.crt'
kata_agent_policy = '/path/to/policy.rego'
init_container_image = 'quay.io/fedora/fedora:44'
init_container_cmd = 'curl http://localhost:8006/cdh/resource/default/attestation-status/status'

# Image-related configuration (optional)
# These KBS URIs are included in the CDH configuration [image] section
container_policy_uri = 'kbs:///default/security-policy/test'
registry_cred_uri = 'kbs:///default/credential/test'
registry_config_uri = 'kbs:///default/registry-configuration/test'

# Custom annotations to add to pods (optional)
# Only annotations with non-empty values will be added
[annotations]
"io.katacontainers.config.runtime.create_container_timeout" = "120"
"io.katacontainers.config.hypervisor.machine_type" = "q35"
"io.katacontainers.config.hypervisor.image" = "/path/to/custom-image"
```

#### Non-Interactive Mode

```bash
kubectl coco init --non-interactive -o /path/to/config.toml
```

### 2. Transform and Apply Manifests

Transform a regular K8s manifest to CoCo:

```bash
kubectl coco apply -f app.yaml
```

#### Advanced Options

```bash
# Use specific runtime class
kubectl coco apply -f app.yaml --runtime-class kata-remote

# Only transform, don't apply
kubectl coco apply -f app.yaml --skip-apply

# Use custom config file
kubectl coco apply -f app.yaml --config /path/to/config.toml

# Add secret download initContainer
kubectl coco apply -f app.yaml --secret "kbs:///default/kbsres1/key1::/keys/key1"

# Add default attestation initContainer
kubectl coco apply -f app.yaml --init-container

# Add custom initContainer with specific image
kubectl coco apply -f app.yaml --init-container --init-container-img custom:latest

# Add custom initContainer with specific command
kubectl coco apply -f app.yaml --init-container --init-container-cmd "echo 'attestation check'"

# Combine multiple options
kubectl coco apply -f app.yaml --init-container --secret "kbs:///default/kbsres1/key1::/keys/key1" --runtime-class kata-remote
```

### 3. Working with Secrets

When you need to inject secrets from the KBS into your containers, use the `--secret` flag:

```bash
kubectl coco apply -f app.yaml --secret "kbs:///default/kbsres1/key1::/keys/key1"
```

The format is: `kbs://resource-uri::target-path`

This will:

1. Create an emptyDir volume (medium: Memory)
2. Add an initContainer that downloads the secret via attestation
3. Mount the volume in both initContainer and app containers

Example initContainer generated:

```yaml
initContainers:
  - name: get-key
    image: registry.access.redhat.com/ubi9/ubi:9.3
    command:
      - sh
      - -c
      - curl -o /keys/key1 http://127.0.0.1:8006/cdh/resource/default/kbsres1/key1
    volumeMounts:
      - name: keys
        mountPath: /keys
```

## What Gets Transformed

When you run `kubectl coco apply`, the tool:

1. **Adds RuntimeClass**: Sets `runtimeClassName` to kata-cc (or your configured runtime)

2. **Generates InitData**: Creates and adds the `io.katacontainers.config.hypervisor.cc_init_data` annotation with:
   - `aa.toml`: Attestation Agent configuration (KBS URL, certs)
   - `cdh.toml`: Confidential Data Hub configuration (includes image security policy, registry credentials, and registry configuration URIs if configured)
   - `policy.rego`: Agent policy (default: exec and logs disabled)
   - Compressed with gzip and base64 encoded

3. **Adds InitContainer** (if `--init-container` flag provided):
   - Prepends an initContainer named 'get-attn-status'
   - Default: Queries attestation status from CDH
   - Custom image: Use `--init-container-img`
   - Custom command: Use `--init-container-cmd`

4. **Adds Secret Download** (if `--secret` flag provided):
   - Creates emptyDir volume with Memory medium
   - Adds initContainer to download secret from KBS
   - Mounts volume in initContainer and app containers
   - Converts kbs:// URIs to CDH endpoint URLs

5. **Adds Custom Annotations**: Applies any custom annotations from config
   - Only annotations with non-empty values are added
   - Common examples: container timeout, hypervisor settings, custom image paths

6. **Creates Backup**: Saves transformed manifest as `*-coco.yaml`

## Example

### Original Manifest

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: my-pod
spec:
  containers:
    - name: my-container
      image: quay.io/fedora/fedora:44
      env:
      - name: MY_SECRET
        valueFrom:
          secretKeyRef:
            name: mysecret
            key: mysecret
```

### After Transformation

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: my-pod
  annotations:
    io.katacontainers.config.hypervisor.cc_init_data: H4sIAAAAAAAA/4yUT2...
spec:
  runtimeClassName: kata-cc
  containers:
    - name: my-container
      image: quay.io/fedora/fedora:44
      env:
      - name: MY_SECRET
        valueFrom:
          secretKeyRef:
            name: sealed-secret
            key: secret
```

## Configuration File Format

The configuration file (`~/.kube/coco-config.toml`) supports:

| Field | Required | Description |
|-------|----------|-------------|
| `trustee_server` | Yes | URL of the Trustee/KBS server |
| `runtime_class` | Yes | Default RuntimeClass to use when --runtime-class is not specified (default: kata-cc) |
| `trustee_ca_cert` | No | Path to Trustee CA certificate |
| `kata_agent_policy` | No | Path to custom agent policy file (.rego) |
| `init_container_image` | No | Default init container image (default: quay.io/fedora/fedora:44) |
| `init_container_cmd` | No | Default init container command (default: attestation check) |
| `container_policy_uri` | No | KBS URI for image security policy (e.g., `kbs:///default/security-policy/test`) |
| `registry_cred_uri` | No | KBS URI for authenticated registry credentials (e.g., `kbs:///default/credential/test`) |
| `registry_config_uri` | No | KBS URI for registry configuration (e.g., `kbs:///default/registry-configuration/test`) |
| `annotations` | No | Map of custom annotations to add to pods (only non-empty values are applied) |

## Policy Files

The default policy disables:
- `ExecProcessRequest` (no exec into pods)
- `ReadStreamRequest` (no log streaming)
- `SetPolicyRequest` (policy changes blocked)

To use a custom policy, specify it in your config:

```toml
kata_agent_policy = '/path/to/custom-policy.rego'
```

See [examples/](examples/) for policy examples.

## Troubleshooting

### "trustee_server is mandatory"

Edit your config file and set the Trustee server URL:

```bash
# Edit the config
vi ~/.kube/coco-config.toml

# Or initialize a new one
kubectl coco init
```

### "failed to load config"

Run `init` first:

```bash
kubectl coco init
```

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
- [Get Resource Feature](https://confidentialcontainers.org/docs/features/get-resource/)

## License

Apache License 2.0

## Contributing

Contributions are welcome! Please submit issues and pull requests to the repository.
