# kubectl-coco

A kubectl plugin to deploy Confidential Containers (CoCo) applications.

## Overview

`kubectl-coco` simplifies the process of transforming regular Kubernetes manifests into CoCo-enabled manifests. It automatically handles:

- RuntimeClass configuration
- InitData generation (aa.toml, cdh.toml, policy.rego)
- Sealed secret conversion
- Manifest transformation and backup

## Features

- **Easy Configuration**: Initialize CoCo configuration and infrastructure with `init` command (non-interactive by default, optional interactive mode)
- **Automatic Transformation**: Convert regular K8s manifests to CoCo-enabled manifests
- **Automatic Secret Conversion**: Detect and convert K8s secrets to sealed secrets automatically
- **InitData Generation**: Automatically generate initdata with proper compression and encoding
- **Backup Management**: Save original manifests with `-coco` suffix
- **kubectl Integration**: Seamlessly apply transformed manifests
- **Trustee Integration**: Generate Trustee KBS configuration for sealed secrets

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

First, initialize CoCo configuration. By default, this runs in non-interactive mode and deploys Trustee to your cluster:

```bash
kubectl coco init
```

This creates `~/.kube/coco-config.toml` with default settings:

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

#### Interactive Mode

By default, `init` runs in non-interactive mode using default values. To enable interactive prompts for all configuration values:

```bash
kubectl coco init --interactive
# or use the short flag
kubectl coco init -i
```

You can also specify configuration via flags in non-interactive mode:

```bash
kubectl coco init --trustee-url https://trustee.example.com -o /path/to/config.toml
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

# Add default attestation initContainer
kubectl coco apply -f app.yaml --init-container

# Add custom initContainer with specific image
kubectl coco apply -f app.yaml --init-container --init-container-img custom:latest

# Add custom initContainer with specific command
kubectl coco apply -f app.yaml --init-container --init-container-cmd "echo 'attestation check'"

# Disable automatic secret conversion
kubectl coco apply -f app.yaml --convert-secrets=false
```

### 3. Working with Secrets

`kubectl-coco` automatically detects and converts K8s secrets to sealed secrets. This happens by default when you run `apply`.

#### Automatic Secret Conversion

When your manifest references K8s secrets, `kubectl-coco` will:

1. **Detect** all secret references (env variables, volumes, envFrom)
2. **Inspect** secrets via kubectl to discover all keys
3. **Convert** each secret key to sealed secret format (`sealed.fakejwsheader.{base64url_json}.fakesignature`)
4. **Create** new K8s secrets with sealed values:
   - Secret name: `{original-name}-sealed` (e.g., `db-creds` → `db-creds-sealed`)
   - Each key contains the sealed secret string instead of the original value
   - When using `--skip-apply`, sealed secret YAML is saved to `*-sealed-secrets.yaml` instead
5. **Update** the manifest to reference sealed secret names:
   - All `secretKeyRef`, `secretRef`, and volume `secretName` fields updated to use `-sealed` suffix
   - Example: `secretKeyRef.name: db-creds` → `secretKeyRef.name: db-creds-sealed`
6. **Generate** Trustee configuration file (`*-trustee-secrets.json`)
7. **Display** setup instructions for adding secrets to Trustee KBS

#### Example: Environment Variable Secrets

**Original manifest:**
```yaml
env:
  - name: DB_PASSWORD
    valueFrom:
      secretKeyRef:
        name: db-creds
        key: password
```

**After transformation:**

1. **New sealed secret is created** in K8s:
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: db-creds-sealed  # Note the -sealed suffix
data:
  password: c2VhbGVkLmZha2Vqd3NoZWFkZXIuZXlKMlpYSnphVzl1SWpvaU1DNHhMakFpTENKMGVYQmxJam9pZG1GMWJIUWlMQ0p1WW0xbElqb2lhMkp6T2k4dkwyUmxabUYxYkhRdlpHSXRZM0psWkhNdmNHRnpjM2R2Y21RaUxDSndjbTkyYVdSbGNpSTZJbXRpY3lJc0luQnliM1pwWkdWeVgzTmxkSFJwYm1keklqcDdmU3dpWVc1dWIzUmhkR2x2Ym5NaU9udDlmUS5mYWtlc2lnbmF0dXJl
```

2. **Manifest is updated** to reference the sealed secret:
```yaml
env:
  - name: DB_PASSWORD
    valueFrom:
      secretKeyRef:
        name: db-creds-sealed  # Updated to use sealed secret name
        key: password           # Same key name
```

#### Example: Volume-Mounted Secrets

**Original manifest:**
```yaml
volumes:
  - name: certs
    secret:
      secretName: tls-secret
```

**After transformation:**

1. **New sealed secret is created** in K8s:
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: tls-secret-sealed  # Note the -sealed suffix
data:
  tls.crt: c2VhbGVkLmZha2Vqd3NoZWFkZXIuZXlK...  # Sealed secret value for tls.crt
  tls.key: c2VhbGVkLmZha2Vqd3NoZWFkZXIuZXlK...  # Sealed secret value for tls.key
```

2. **Manifest is updated** to reference the sealed secret:
```yaml
volumes:
  - name: certs
    secret:
      secretName: tls-secret-sealed  # Updated to use sealed secret name
```

#### Trustee Configuration Output

After conversion, a Trustee configuration file is generated (e.g., `app-trustee-secrets.json`):

```json
{
  "secrets": [
    {
      "resourceUri": "kbs:///default/db-creds/password",
      "sealedSecret": "sealed.fakejwsheader.eyJ2ZXJzaW9u...",
      "json": {
        "version": "0.1.0",
        "type": "vault",
        "name": "kbs:///default/db-creds/password",
        "provider": "kbs",
        "provider_settings": {},
        "annotations": {}
      }
    }
  ]
}
```

You must add these secrets to your Trustee KBS before deploying the application.

#### How Sealed Secrets Work

The sealed secret conversion creates a secure flow:

1. **In K8s**: A sealed secret is created (e.g., `db-creds-sealed`) containing the sealed format string
   - The sealed string has the format: `sealed.fakejwsheader.{base64url_json}.fakesignature`
   - The JSON payload contains the KBS resource URI (e.g., `kbs:///default/db-creds/password`)

2. **In Trustee KBS**: You store the actual secret value at the KBS URI
   - Use the generated `*-trustee-secrets.json` file to configure Trustee
   - The actual password/credential is stored securely in Trustee

3. **At Runtime**: The pod retrieves secrets through attestation
   - Pod reads the sealed secret from K8s (gets the sealed format string)
   - Pod performs attestation with Trustee KBS
   - Trustee validates the attestation and returns the actual secret value
   - Pod uses the actual secret value in the application

This ensures secrets are never exposed in plaintext in the K8s cluster.

#### Secret Conversion Flag

```bash
# Disable automatic secret conversion (show warning only)
kubectl coco apply -f app.yaml --convert-secrets=false
```

## What Gets Transformed

When you run `kubectl coco apply`, the tool:

1. **Adds RuntimeClass**: Sets `runtimeClassName` to kata-cc (or your configured runtime)

2. **Converts Secrets** (automatic, unless `--convert-secrets=false`):
   - Detects K8s secret references in the manifest
   - Inspects secrets via kubectl to discover all keys
   - Converts each secret key to sealed secret format (`sealed.fakejwsheader.{base64url_json}.fakesignature`)
   - Creates new K8s secrets with `-sealed` suffix containing sealed values:
     * Example: `db-creds` → `db-creds-sealed`
     * When using `--skip-apply`, generates YAML file instead of creating in cluster
   - Updates manifest to reference sealed secret names:
     * `secretKeyRef.name`: `db-creds` → `db-creds-sealed`
     * Volume `secretName`: `tls-secret` → `tls-secret-sealed`
     * `envFrom.secretRef.name`: `app-config` → `app-config-sealed`
   - Generates Trustee configuration file with all sealed secrets and their KBS URIs
   - Displays setup instructions for adding secrets to Trustee KBS

3. **Generates InitData**: Creates and adds the `io.katacontainers.config.hypervisor.cc_init_data` annotation with:
   - `aa.toml`: Attestation Agent configuration (KBS URL, certs)
   - `cdh.toml`: Confidential Data Hub configuration (includes image security policy, registry credentials, and registry configuration URIs if configured)
   - `policy.rego`: Agent policy (default: exec and logs disabled)
   - Compressed with gzip and base64 encoded

4. **Adds InitContainer** (if `--init-container` flag provided):
   - Prepends an initContainer named 'get-attn-status'
   - Default: Queries attestation status from CDH
   - Custom image: Use `--init-container-img`
   - Custom command: Use `--init-container-cmd`

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
  namespace: default
spec:
  containers:
    - name: my-container
      image: quay.io/fedora/fedora:44
      env:
      - name: DB_PASSWORD
        valueFrom:
          secretKeyRef:
            name: db-creds
            key: password
```

### After Transformation

1. **New sealed secret is created** in K8s (`db-creds-sealed`):
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: db-creds-sealed
  namespace: default
data:
  password: c2VhbGVkLmZha2Vqd3NoZWFkZXIuZXlKMlpYSnphVzl1SWpvaU1DNHhMakFpTENKMGVYQmxJam9pZG1GMWJIUWlMQ0p1WW0xbElqb2lhMkp6T2k4dkwyUmxabUYxYkhRdlpHSXRZM0psWkhNdmNHRnpjM2R2Y21RaUxDSndjbTkyYVdSbGNpSTZJbXRpY3lJc0luQnliM1pwWkdWeVgzTmxkSFJwYm1keklqcDdmU3dpWVc1dWIzUmhkR2x2Ym5NaU9udDlmUS5mYWtlc2lnbmF0dXJl
```

2. **Pod manifest is updated** to reference the sealed secret:
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: my-pod
  namespace: default
  annotations:
    io.katacontainers.config.hypervisor.cc_init_data: H4sIAAAAAAAA/4yUT2...
spec:
  runtimeClassName: kata-cc
  containers:
    - name: my-container
      image: quay.io/fedora/fedora:44
      env:
      - name: DB_PASSWORD
        valueFrom:
          secretKeyRef:
            name: db-creds-sealed  # Updated to reference sealed secret
            key: password
```

### Trustee Configuration Generated

File: `my-pod-trustee-secrets.json`

```json
{
  "secrets": [
    {
      "resourceUri": "kbs:///default/db-creds/password",
      "sealedSecret": "sealed.fakejwsheader.eyJ2ZXJzaW9uIjoiMC4xLjAi...",
      "json": {
        "version": "0.1.0",
        "type": "vault",
        "name": "kbs:///default/db-creds/password",
        "provider": "kbs",
        "provider_settings": {},
        "annotations": {}
      }
    }
  ]
}
```

**Important:** You must add the actual secret values to your Trustee KBS using the URIs above (e.g., `kbs:///default/db-creds/password`). The sealed secrets in K8s (`db-creds-sealed`) only contain the sealed format strings that reference these KBS URIs. The pod will retrieve the actual secret values from Trustee KBS during attestation.

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
