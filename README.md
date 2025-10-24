# kubectl-coco

A kubectl plugin to deploy Confidential Containers (CoCo) applications.

## Overview

`kubectl-coco` simplifies the process of transforming regular Kubernetes manifests into CoCo-enabled manifests. It automatically handles:

- RuntimeClass configuration
- InitData generation (aa.toml, cdh.toml, policy.rego)
- Sealed secret conversion
- Manifest transformation and backup

## Features

- **Interactive Configuration**: Create CoCo configuration with `create-config` command
- **Automatic Transformation**: Convert regular K8s manifests to CoCo-enabled manifests
- **Sealed Secrets**: Generate sealed secrets using coco-tools
- **InitData Generation**: Automatically generate initdata with proper compression and encoding
- **Backup Management**: Save original manifests with `-coco` suffix
- **kubectl Integration**: Seamlessly apply transformed manifests

## Prerequisites

- Go 1.21 or later (for building from source)
- kubectl (for applying manifests)
- podman or docker (for sealed secret generation)

## Installation

### From Source

```bash
git clone https://github.com/confidential-containers/coco-ctl
cd coco-ctl
make build
sudo make install
```

### Manual Installation

```bash
go build -o kubectl-coco .
sudo mv kubectl-coco /usr/local/bin/
```

## Usage

### 1. Create Configuration

First, create a CoCo configuration file:

```bash
kubectl coco create-config
```

This creates `~/.kube/coco-config.toml` with the following settings:

```toml
# Trustee server URL (mandatory)
trustee_server = 'https://your-trustee-server:8080'

# RuntimeClass to use (default)
runtime_classes = ['kata-cc', 'kata-remote']

# Optional settings
trustee_ca_cert = '/path/to/ca.crt'
kata_agent_policy = '/path/to/policy.rego'
init_container_image = 'custom-init:latest'
```

#### Non-Interactive Mode

```bash
kubectl coco create-config --non-interactive -o /path/to/config.toml
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

# Convert secrets to sealed secrets
kubectl coco apply -f app.yaml --resource-uri "kbs:///default/kbsres1/key1"
```

### 3. Working with Sealed Secrets

When your manifest contains secrets, use the `--resource-uri` flag:

```bash
kubectl coco apply -f app.yaml --resource-uri "kbs:///default/kbsres1/key1"
```

This will:
1. Generate a sealed secret using coco-tools
2. Print the kubectl command to create the secret
3. Update the manifest to use the sealed secret

Example output:
```
Generated sealed secret: sealed.fakejwsheader.eyJ2ZXJzaW...fakesignature
You need to create a Kubernetes secret with this value:
kubectl create secret generic sealed-secret --from-literal=secret=sealed.fakejwsheader...
```

## What Gets Transformed

When you run `kubectl coco apply`, the tool:

1. **Adds RuntimeClass**: Sets `runtimeClassName` to kata-cc (or your configured runtime)

2. **Generates InitData**: Creates and adds the `io.katacontainers.config.hypervisor.cc_init_data` annotation with:
   - `aa.toml`: Attestation Agent configuration (KBS URL, certs)
   - `cdh.toml`: Confidential Data Hub configuration
   - `policy.rego`: Agent policy (default: exec and logs disabled)
   - Compressed with gzip and base64 encoded

3. **Converts Secrets** (if `--resource-uri` provided):
   - Detects secret references in env vars and volumes
   - Generates sealed secrets via coco-tools
   - Replaces secret names with 'sealed-secret'

4. **Creates Backup**: Saves transformed manifest as `*-coco.yaml`

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
| `runtime_classes` | Yes | List of RuntimeClasses (default: kata-cc, kata-remote) |
| `trustee_ca_cert` | No | Path to Trustee CA certificate |
| `kata_agent_policy` | No | Path to custom agent policy file (.rego) |
| `init_container_image` | No | Custom init container for attestation |
| `container_policy_uri` | No | Container policy URI |
| `registry_cred_uri` | No | Registry credentials URI |
| `registry_config_uri` | No | Registry configuration URI |

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

### "No container runtime found"

Sealed secret conversion requires podman or docker. Install one:

```bash
# macOS
brew install podman
podman machine init
podman machine start

# Linux
sudo dnf install podman  # Fedora/RHEL
sudo apt install podman  # Ubuntu/Debian
```

### "trustee_server is mandatory"

Edit your config file and set the Trustee server URL:

```bash
# Edit the config
vi ~/.kube/coco-config.toml

# Or create a new one
kubectl coco create-config
```

### "failed to load config"

Run `create-config` first:

```bash
kubectl coco create-config
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
