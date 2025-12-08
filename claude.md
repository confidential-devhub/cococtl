# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

kubectl-coco is a kubectl plugin that transforms regular Kubernetes manifests into Confidential Containers (CoCo) enabled manifests. It automates RuntimeClass configuration, secret conversion to sealed format, imagePullSecrets handling, initdata generation, and Trustee KBS deployment/management.

**Target users**: Developers testing CoCo applications (not for production deployments)

## Common Commands

### Build and Test
```bash
# Build binary
make build

# Run integration tests (all tests)
make test

# Run specific test
make test TEST=TestConfigLoad

# Run specific test pattern
make test TEST=TestSecret

# Format code
make fmt

# Run go vet
make vet

# Run linter (requires golangci-lint)
make lint

# Install locally
sudo make install

# Clean build artifacts
make clean
```

### Development Workflow
```bash
# Build and test locally
./kubectl-coco init --help
./kubectl-coco apply --help
./kubectl-coco completion bash  # Generate shell completion

# Test transformation without applying
./kubectl-coco apply -f examples/pod.yaml --skip-apply

# Verify output
cat examples/pod-coco.yaml
```

### Release
```bash
# Build for specific platform
make release GOOS=linux GOARCH=amd64

# Build for all platforms
make release-all

# Build with custom version
VERSION=v1.0.0 make build
```

**Versioning**: Version is automatically set from git tags using `git describe
--tags --always --dirty`. The version is injected at build time via ldflags
into `cmd.version` variable. Default version is "dev" if git is not available.

## Architecture Overview

### Core Transformation Pipeline

The `apply` command performs transformations in this order:
1. **Detect secrets** (pkg/secrets) - Scan manifest for secret references (env, envFrom, volumes, imagePullSecrets)
2. **Convert to sealed secrets** (pkg/sealed) - Create sealed format with KBS URIs
3. **Upload to Trustee KBS** (pkg/trustee) - Automatically populate KBS repository via kubectl exec
4. **Set RuntimeClass** (pkg/manifest) - Add `kata-cc` runtime to spec
5. **Generate initdata** (pkg/initdata) - Create aa.toml, cdh.toml, policy.rego annotation
6. **Add custom annotations** (pkg/manifest) - Apply config-defined annotations
7. **Inject initContainer** (pkg/manifest) - Optional attestation verification container
8. **Save and apply** - Backup to *-coco.yaml, optionally apply via kubectl

### Key Packages

**pkg/manifest**: Generic manifest manipulation using `map[string]interface{}` for flexibility across all K8s resource types (Pod, Deployment, StatefulSet, ReplicaSet, Job, DaemonSet). Critical insight: Annotations must be placed on pod templates for workload resources, not top-level metadata.

**pkg/secrets**: Secret detection and conversion. Scans containers for `env[].valueFrom.secretKeyRef`, `envFrom[].secretRef`, and `volumes[].secret`. Also detects imagePullSecrets from manifest or default service account.

**pkg/sealed**: Creates sealed secret format: `sealed.fakejwsheader.{base64url_json}.fakesignature` where JSON contains KBS URI like `kbs:///namespace/secret-name/key`.

**pkg/initdata**: Generates gzip-compressed, base64-encoded initdata annotation containing three TOML files (aa.toml for attestation agent, cdh.toml for confidential data hub, policy.rego for kata agent policy). Handles optional imagePullSecrets URIs in CDH configuration.

**pkg/trustee**: Deploys all-in-one Trustee KBS using kubectl. Generates Ed25519 keypair for auth. Automatically creates default attestation status secret at `/opt/confidential-containers/kbs/repository/default/attestation-status/status` for init container verification.

**pkg/config**: Manages `~/.kube/coco-config.toml` with TOML format. Validates mandatory fields (trustee_server, runtime_class).

### Critical Implementation Details

**Annotation Placement**: The `io.katacontainers.config.hypervisor.cc_init_data` annotation MUST be placed at:
- Pod: `metadata.annotations`
- Deployment/StatefulSet/etc: `spec.template.metadata.annotations`

This is handled by `GetPodAnnotationsPath()` in pkg/manifest/manifest.go.

**Secret Upload Flow**: When converting secrets, the tool uses `kubectl exec` to write decoded secret values directly into the Trustee KBS pod at `/opt/confidential-containers/kbs/repository/{namespace}/{secret-name}/{key}`. This is a temporary solution for development/testing.

**ImagePullSecrets Handling**: imagePullSecrets remain in the manifest (needed by CRI-O for image pulling) AND are uploaded to KBS (for runtime attestation verification). Only the first imagePullSecret is used in CDH configuration. The `.dockerconfigjson` key has its leading dot stripped when creating the KBS URI.

**Workload Resource Support**: All transformations work via helper functions that detect resource kind and manipulate either `spec` (Pod) or `spec.template.spec` (workload resources). See `GetPodSpec()`, `GetContainers()`, etc. in pkg/manifest/manifest.go.

## Configuration File Structure

Location: `~/.kube/coco-config.toml`

**Mandatory fields**:
- `trustee_server`: Trustee KBS URL (e.g., `https://trustee-kbs.default.svc.cluster.local:8080`)
- `runtime_class`: CoCo runtime (e.g., `kata-cc`)

**Optional fields**:
- `trustee_ca_cert`: Path to CA certificate for Trustee
- `kata_agent_policy`: Path to custom policy.rego file
- `init_container_image`: Default init container image
- `init_container_cmd`: Default init container command
- `container_policy_uri`: KBS URI for image security policy
- `registry_cred_uri`: KBS URI for registry credentials
- `registry_config_uri`: KBS URI for registry configuration

**Custom annotations section**: `[annotations]` - Any non-empty values are applied to pod templates

## Testing Approach

Tests are in `integration_test/` and use the Go testing package. They cover:
- Config loading/validation (config_test.go)
- Sealed secret generation (sealed_test.go)
- Secret detection/conversion (secrets_test.go)
- InitData generation (initdata_test.go)
- Manifest transformation (manifest_test.go)
- End-to-end workflows (workflow_test.go)
- Trustee deployment (trustee_test.go)

Run tests with `make test TEST=<pattern>` to filter by test name.

## Important Dependencies

- `github.com/spf13/cobra`: CLI framework - all commands in cmd/
- `gopkg.in/yaml.v3`: YAML parsing for K8s manifests
- `github.com/pelletier/go-toml/v2`: TOML config parsing
- Standard library: `encoding/base64` (sealed secrets), `compress/gzip` (initdata), `os/exec` (kubectl commands)

## Common Gotchas

1. **YAML type assertions**: Manifest data is `map[string]interface{}` - always check type assertions and handle missing fields gracefully
2. **Namespace resolution**: Manifests may not specify namespace - default to "default" or current kubectl context namespace
3. **Secret key variations**: imagePullSecrets use `.dockerconfigjson` but KBS URIs strip the leading dot
4. **Resource type detection**: Use `GetKind()` to branch logic between Pod and workload resources
5. **Path validation**: Manifest loading includes directory traversal protection (see pkg/manifest/manifest.go:20-46)
6. **InitContainer prepending**: When adding init containers, prepend (don't append) so attestation runs first

## Code Patterns to Follow

**Error handling**: Always wrap errors with context using `fmt.Errorf("descriptive message: %w", err)`

**Manifest transformation**: Use helper functions like `GetPodSpec()`, `GetContainers()`, `GetPodAnnotationsPath()` to handle both Pod and workload resources

**Flag validation**: Validate flag combinations in RunE function before processing (see cmd/apply.go:71-120)

**Backup creation**: Always create `*-coco.yaml` backup before modifying manifests

**kubectl integration**: Use `exec.Command("kubectl", ...)` for K8s operations with proper error handling

## Development Philosophy

This project follows an incremental development approach with small, focused commits. When adding features:
- Each commit should be buildable and testable
- Update README.md and TRANSFORMATIONS.md with new functionality
- Add example manifests if introducing new transformation types
- Test manually with `--skip-apply` before committing
- Document architectural decisions
