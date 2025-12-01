# kubectl-coco

A kubectl plugin to deploy Confidential Containers (CoCo) applications.

`kubectl-coco` is designed primarily for developers to CoCo-fy their applications and test them with Trustee, the Remote Attestation Solution for CoCo. It's not meant for production deployment of CoCo applications.
Read more about CoCo at [confidentialcontainers.org](https://confidentialcontainers.org/).

## Overview

`kubectl-coco` simplifies the process of transforming regular Kubernetes manifests into CoCo-enabled manifests. It automatically handles:

- **RuntimeClass Configuration**: Sets the appropriate CoCo runtime
- **Secrets Management**: Converts K8s secrets to sealed secrets and uploads to locally deployed Trustee KBS
- **ImagePullSecrets**: Handles private registry credentials with automatic Trustee KBS integration
- **InitData Generation**: Creates aa.toml, cdh.toml, and policy.rego configurations


## Features

- ✅ **Trustee deployment**: Deploy a Trustee instance in the cluster for testing
- ✅ **Automatic Secret Conversion**: Detects and converts K8s secrets to sealed format including updating Trustee KBS with the secrets
- ✅ **ImagePullSecrets Support**: Handles private registry credentials with Trustee KBS integration
- ✅ **Secure Access Sidecar**: Optional mTLS-secured sidecar for status reporting and secure port forwarding (see [sidecar/README.md](sidecar/README.md))
- ✅ **Multi-Resource Support**: Works with Pod, Deployment, StatefulSet, ReplicaSet, Job, DaemonSet
- ✅ **InitData Generation**: Creates properly formatted and encoded configurations
- ✅ **Backup Management**: Saves transformed manifests with `-coco` suffix

## Quick Start

### 1. Install

```bash
# Download latest release
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
if [ "$ARCH" = "x86_64" ]; then ARCH="amd64"; fi
curl -LO "https://github.com/confidential-devhub/cococtl/releases/latest/download/kubectl-coco-${OS}-${ARCH}"

# Install
sudo install -m 0755 kubectl-coco-${OS}-${ARCH} /usr/local/bin/kubectl-coco

# Verify
kubectl coco --version
```

See [Installation](#installation) for detailed options.

### 2. Initialize

Deploy Trustee and create configuration:

```bash
kubectl coco init
```

This creates `~/.kube/coco-config.toml` and deploys Trustee to your cluster.

### 3. Transform and Deploy

```bash
kubectl coco apply -f your-app.yaml
```

That's it! Your application is now CoCo-enabled with:
- Secrets converted to sealed format
- ImagePullSecrets configured for KBS
- Secrets automatically uploaded to Trustee KBS
- Proper runtime and initdata configured

## What Gets Transformed

`kubectl-coco` performs these transformations:

1. **Sets RuntimeClass** to `kata-cc` (configurable)
2. **Converts Secrets**:
   - Detects all secret references (env, envFrom, volumes)
   - Creates sealed secrets with `-sealed` suffix
   - **Automatically uploads** actual secret values to Trustee KBS
   - Updates manifest to use sealed secret names
3. **Handles ImagePullSecrets**:
   - Keeps imagePullSecrets in manifest (for CRI-O)
   - **Automatically uploads** credentials to Trustee KBS
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
   curl -LO "https://github.com/confidential-devhub/cococtl/releases/latest/download/kubectl-coco-${OS}-${ARCH}"
   ```

   For a specific version:
   ```bash
   VERSION=v0.1.0
   curl -LO "https://github.com/confidential-devhub/cococtl/releases/download/${VERSION}/kubectl-coco-${OS}-${ARCH}"
   ```

2. **Validate (optional):**

   ```bash
   curl -LO "https://github.com/confidential-devhub/cococtl/releases/latest/download/kubectl-coco-${OS}-${ARCH}.sha256"
   echo "$(cat kubectl-coco-${OS}-${ARCH}.sha256)" | sha256sum --check
   ```

3. **Install:**

   System-wide (requires sudo):
   ```bash
   sudo install -m 0755 kubectl-coco-${OS}-${ARCH} /usr/local/bin/kubectl-coco
   ```

   Or user directory:
   ```bash
   mkdir -p ~/.local/bin
   install -m 0755 kubectl-coco-${OS}-${ARCH} ~/.local/bin/kubectl-coco
   export PATH=$PATH:~/.local/bin  # Add to ~/.bashrc or ~/.zshrc
   ```

4. **Verify:**

   ```bash
   kubectl coco --version
   ```

### From Source

```bash
git clone https://github.com/confidential-devhub/cococtl
cd cococtl
make build
sudo make install
```

## Usage

### Initialize Configuration

Deploy Trustee and create configuration (non-interactive by default):

```bash
kubectl coco init
```

This deploys Trustee to your current namespace and creates `~/.kube/coco-config.toml`.

**Interactive mode:**

```bash
kubectl coco init --interactive  # or -i
```

**With custom Trustee:**

```bash
kubectl coco init --trustee-url https://trustee.example.com:8080
```

### Transform and Apply Manifests

**Basic usage:**

```bash
kubectl coco apply -f app.yaml
```

**Common options:**
```bash
# Only transform, don't apply
kubectl coco apply -f app.yaml --skip-apply

# Use specific runtime class
kubectl coco apply -f app.yaml --runtime-class kata-remote

# Add attestation initContainer
kubectl coco apply -f app.yaml --init-container

# Enable secure access sidecar
kubectl coco apply -f app.yaml --sidecar

# Disable automatic secret conversion
kubectl coco apply -f app.yaml --convert-secrets=false

# Use custom config file
kubectl coco apply -f app.yaml --config /path/to/config.toml
```

See [TRANSFORMATIONS.md](TRANSFORMATIONS.md) for detailed description on the transformations.

### Secure Access Sidecar

The secure access sidecar provides mTLS-secured HTTPS access to your CoCo pods.

**One-time setup:**

```bash
kubectl coco init --enable-sidecar
```

**Deploy with sidecar:**

```bash
# Basic usage
kubectl coco apply -f app.yaml --sidecar

# Enable port forwarding from primary container
kubectl coco apply -f app.yaml --sidecar --sidecar-port-forward 8888

# Custom SANs for LoadBalancer or Ingress
kubectl coco apply -f app.yaml --sidecar \
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

**Note:** TLS certificates are auto-generated per-app during `kubectl coco apply --sidecar`.

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
