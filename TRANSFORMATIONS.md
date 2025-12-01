# Manifest Transformations

This document explains in detail how `kubectl-coco` transforms regular Kubernetes manifests into Confidential Containers (CoCo) enabled manifests.

## Table of Contents

- [Supported Resource Types](#supported-resource-types)
- [Transformation Steps](#transformation-steps)
- [RuntimeClass Configuration](#runtimeclass-configuration)
- [Secret Conversion](#secret-conversion)
- [ImagePullSecrets Handling](#imagepullsecrets-handling)
- [InitData Generation](#initdata-generation)
- [InitContainer Injection](#initcontainer-injection)
- [Custom Annotations](#custom-annotations)
- [Examples](#examples)

## Supported Resource Types

`kubectl-coco` supports the following Kubernetes resource types:

- **Pod**: Direct pod resources
- **Deployment**: Deployment workloads
- **StatefulSet**: Stateful applications
- **DaemonSet**: Node-level daemons
- **ReplicaSet**: Replica management
- **Job**: Batch jobs

For workload resources (Deployment, StatefulSet, etc.), transformations are applied to the pod template (`spec.template.spec`), ensuring all pods created by the workload are CoCo-enabled.

## Transformation Steps

When you run `kubectl coco apply -f manifest.yaml`, the tool performs these transformations:

### 1. RuntimeClass Configuration

Sets the `runtimeClassName` field to enable the CoCo runtime (default: `kata-cc`).

**Pod:**
```yaml
spec:
  runtimeClassName: kata-cc
```

**Deployment/StatefulSet/etc:**
```yaml
spec:
  template:
    spec:
      runtimeClassName: kata-cc
```

### 2. Secret Conversion

Automatically detects and converts Kubernetes secrets to sealed secrets (unless `--convert-secrets=false`).

#### Detection

The tool scans the manifest for secret references in:

- **Environment Variables**: `env[].valueFrom.secretKeyRef`
- **Environment From**: `envFrom[].secretRef`
- **Volumes**: `volumes[].secret.secretName`

#### Conversion Process

For each secret found:

1. **Inspect via kubectl**: Retrieves all keys in the secret
2. **Generate sealed secrets**: Converts each key to sealed format
   ```
   sealed.fakejwsheader.{base64url_json}.fakesignature
   ```
3. **Create K8s sealed secret**: New secret with `-sealed` suffix
   - Original: `db-creds`
   - Sealed: `db-creds-sealed`
4. **Update manifest**: Replace all references to use sealed secret name
5. **Upload to KBS** (automatic): Adds actual secret values to Trustee KBS repository
6. **Generate config**: Creates `*-trustee-secrets.json` for reference

#### Sealed Secret Format

Here is an example:

```json
{
  "version": "0.1.0",
  "type": "vault",
  "name": "kbs:///namespace/secret-name/key",
  "provider": "kbs",
  "provider_settings": {},
  "annotations": {}
}
```

This JSON is base64url-encoded and wrapped in the sealed secret format.

#### Automatic KBS Upload

When secrets are converted, `kubectl-coco` automatically:

1. Extracts the actual secret value from the K8s secret (base64-decoded)
2. Uploads it to the Trustee KBS repository at the path:
   ```
   /opt/confidential-containers/kbs/repository/{namespace}/{secret-name}/{key}
   ```
3. The file contains the decoded secret value (plaintext)

**Example**: For secret `db-creds` in namespace `default` with key `password`:
- **KBS path**: `/opt/confidential-containers/kbs/repository/default/db-creds/password`
- **File content**: The actual password value

This happens automatically during the `apply` command (when `--skip-apply` is false).

#### Example Transformations

**Environment Variable (before):**
```yaml
env:
  - name: DB_PASSWORD
    valueFrom:
      secretKeyRef:
        name: db-creds
        key: password
```

**Environment Variable (after):**
```yaml
env:
  - name: DB_PASSWORD
    valueFrom:
      secretKeyRef:
        name: db-creds-sealed  # Updated name
        key: password
```

**Volume Mount (before):**
```yaml
volumes:
  - name: tls-certs
    secret:
      secretName: tls-secret
```

**Volume Mount (after):**
```yaml
volumes:
  - name: tls-certs
    secret:
      secretName: tls-secret-sealed  # Updated name
```

### 3. ImagePullSecrets Handling

`kubectl-coco` handles imagePullSecrets for pulling images from private registries.

#### Detection

The tool checks for imagePullSecrets in two places:

1. **Manifest spec**: `spec.imagePullSecrets` (Pod) or `spec.template.spec.imagePullSecrets` (Deployment, etc.)
2. **Default service account**: If no imagePullSecrets in manifest, checks the `default` service account in the pod's namespace

#### Processing

For imagePullSecrets found:

1. **Keep in manifest**: imagePullSecrets remain in the manifest (CRI-O needs them for image pulls)
2. **Upload to KBS** (automatic): Adds imagePullSecret data to Trustee KBS
3. **Add to initdata**: Includes `authenticated_registry_credentials_uri` in CDH configuration

**Note**: Only the **first** imagePullSecret is used, as CDH supports only one authenticated registry credential URI.

#### Automatic KBS Upload

When imagePullSecrets are detected, `kubectl-coco` automatically:

1. Retrieves the secret data from K8s (typically `.dockerconfigjson`)
2. Strips the leading dot from the key name (`.dockerconfigjson` → `dockerconfigjson`)
3. Uploads to KBS repository at:
   ```
   /opt/confidential-containers/kbs/repository/{namespace}/{secret-name}/{key}
   ```
4. Adds the KBS URI to initdata CDH configuration

**Example**: For imagePullSecret `regcred` in namespace `default` with key `.dockerconfigjson`:
- **KBS path**: `/opt/confidential-containers/kbs/repository/default/regcred/dockerconfigjson`
- **Initdata CDH**: `authenticated_registry_credentials_uri = "kbs:///default/regcred/dockerconfigjson"`

#### Example

**Manifest with imagePullSecrets:**
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  template:
    spec:
      containers:
      - name: app
        image: private-registry.example.com/myapp:v1.0
      imagePullSecrets:
      - name: regcred
```

**After transformation:**
- imagePullSecrets remain in manifest (unchanged)
- Secret uploaded to KBS at `/opt/confidential-containers/kbs/repository/default/regcred/dockerconfigjson`
- initdata includes:
  ```toml
  [credentials]
  authenticated_registry_credentials_uri = "kbs:///default/regcred/dockerconfigjson"
  ```

### 4. InitData Generation

Generates the `io.katacontainers.config.hypervisor.cc_init_data` annotation containing:

#### aa.toml (Attestation Agent)

```toml
[token_configs.coco_as]
url = 'https://your-trustee-server:8080'
cert_file = '/path/to/ca.crt'  # If configured
```

#### cdh.toml (Confidential Data Hub)

```toml
[image]
# Only included if configured in coco-config.toml
image_security_policy_uri = "kbs:///default/security-policy/test"
# Only included if imagePullSecrets detected or configured in coco-config.toml
authenticated_registry_credentials_uri = "kbs:///default/credential/test"
registry_config_uri = "kbs:///default/registry-configuration/test"
```

#### policy.rego (Agent Policy)

Default policy disables:
- `ExecProcessRequest`: No exec into pods
- `SetPolicyRequest`: Policy changes blocked

Logs are enabled by default (`ReadStreamRequest := true`).

Custom policy can be specified in config.

#### Encoding

All three files are:
1. Combined into a single structure
2. Compressed with gzip
3. Base64-encoded
4. Added as annotation value

#### Annotation Placement

**Critical**: The annotation is placed differently based on resource type:

**Pod:**
```yaml
metadata:
  annotations:
    io.katacontainers.config.hypervisor.cc_init_data: "H4sIAAAA..."
```

**Deployment/StatefulSet/ReplicaSet/Job/DaemonSet:**
```yaml
spec:
  template:
    metadata:
      annotations:
        io.katacontainers.config.hypervisor.cc_init_data: "H4sIAAAA..."
```

This ensures the annotation is applied to the actual pods, not just the workload controller.

### 5. InitContainer Injection

When `--init-container` flag is provided, prepends an initContainer for attestation verification.

#### Default InitContainer

```yaml
initContainers:
  - name: get-attn-status
    image: quay.io/fedora/fedora:44  # Configurable
    command:
      - sh
      - -c
      - curl http://localhost:8006/cdh/resource/default/attestation-status/status
```

This verifies attestation succeeded before starting main containers.

#### Custom InitContainer

```bash
# Custom image
kubectl coco apply -f app.yaml --init-container --init-container-img custom:latest

# Custom command
kubectl coco apply -f app.yaml --init-container --init-container-cmd "echo 'attestation verified'"
```

### 6. Custom Annotations

Applies custom annotations from the config file to pods.

**Config (`~/.kube/coco-config.toml`):**
```toml
[annotations]
"io.katacontainers.config.runtime.create_container_timeout" = "120"
"io.katacontainers.config.hypervisor.machine_type" = "q35"
```

Only annotations with non-empty values are applied, and they are placed in the correct location (pod metadata for Pods, pod template metadata for workload resources).

## Examples

### Complete Pod Transformation

**Before:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: my-app
  namespace: default
spec:
  containers:
  - name: app
    image: private-registry.example.com/myapp:v1.0
    env:
    - name: DB_PASSWORD
      valueFrom:
        secretKeyRef:
          name: db-creds
          key: password
  imagePullSecrets:
  - name: regcred
```

**After:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: my-app
  namespace: default
  annotations:
    io.katacontainers.config.hypervisor.cc_init_data: "H4sIAAAAAAAA/4yUT2..."
spec:
  runtimeClassName: kata-cc
  containers:
  - name: app
    image: private-registry.example.com/myapp:v1.0
    env:
    - name: DB_PASSWORD
      valueFrom:
        secretKeyRef:
          name: db-creds-sealed  # Changed
          key: password
  imagePullSecrets:
  - name: regcred  # Unchanged, still needed for CRI-O
```

**KBS Repository (automatically created):**
```
/opt/confidential-containers/kbs/repository/default/db-creds/password
/opt/confidential-containers/kbs/repository/default/regcred/dockerconfigjson
/opt/confidential-containers/kbs/repository/default/attestation-status/status
```

### Complete Deployment Transformation

**Before:**
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web-app
  namespace: production
spec:
  replicas: 3
  selector:
    matchLabels:
      app: web
  template:
    metadata:
      labels:
        app: web
    spec:
      containers:
      - name: nginx
        image: private-registry.example.com/nginx:1.21
        env:
        - name: API_KEY
          valueFrom:
            secretKeyRef:
              name: api-secrets
              key: key
      imagePullSecrets:
      - name: registry-creds
```

**After:**
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web-app
  namespace: production
spec:
  replicas: 3
  selector:
    matchLabels:
      app: web
  template:
    metadata:
      labels:
        app: web
      annotations:
        io.katacontainers.config.hypervisor.cc_init_data: "H4sIAAAAAAAA/4yUT2..."
    spec:
      runtimeClassName: kata-cc
      containers:
      - name: nginx
        image: private-registry.example.com/nginx:1.21
        env:
        - name: API_KEY
          valueFrom:
            secretKeyRef:
              name: api-secrets-sealed  # Changed
              key: key
      imagePullSecrets:
      - name: registry-creds  # Unchanged
```

**Trustee KBS Resources (automatically created):**
```
/opt/confidential-containers/kbs/repository/production/api-secrets/key
/opt/confidential-containers/kbs/repository/production/registry-creds/dockerconfigjson
/opt/confidential-containers/kbs/repository/default/attestation-status/status
```