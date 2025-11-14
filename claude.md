# kubectl-coco Development with Claude Code

This document describes the development process and architecture of kubectl-coco, a kubectl plugin for Confidential Containers (CoCo), built with assistance from Claude Code.

## Project Overview

kubectl-coco is a command-line tool that transforms regular Kubernetes manifests into CoCo-enabled manifests, handling:
- RuntimeClass configuration
- InitData generation (attestation agent, confidential data hub, policies)
- Secret download via attestation
- InitContainer injection
- Manifest transformation and backup

## Development Approach

### Incremental Commits Strategy

The project was built using small, focused commits, each addressing a specific feature:

1. **Initial commit**: Project setup with Go module and Cobra CLI framework
2. **Add create-config**: Command and config package for TOML configuration
3. **Add apply command**: Basic manifest transformation with YAML parsing
4. **Implement initdata**: Generation with gzip compression and base64 encoding
5. **Add sealed secret**: Conversion using external coco-tools binary (later rewritten)
6. **Add README and Makefile**: Documentation and build automation
7. **Add initContainer**: Injection support with customizable options
8. **Rename --resource-uri**: To --secret with new format specification
9. **Rewrite sealed package**: With base64url encoding (removed external binary dependency)
10. **Add secret download**: InitContainer with volume management
11. **Update README**: Document new --secret flag functionality

This approach ensured:
- Each commit is buildable and testable
- Clear git history for code review
- Easy rollback if needed
- Logical feature separation

## Architecture

### Package Structure

```
cococtl/
├── cmd/                    # CLI commands (Cobra-based)
│   ├── root.go            # Root command and common utilities
│   ├── createconfig.go    # Interactive config creation
│   └── apply.go           # Manifest transformation and apply
├── pkg/
│   ├── config/            # TOML configuration management
│   │   └── config.go      # Load/Save/Validate config
│   ├── manifest/          # YAML manifest manipulation
│   │   └── manifest.go    # Load/Save/Transform manifests
│   ├── initdata/          # InitData generation
│   │   └── initdata.go    # Generate aa.toml, cdh.toml, policy.rego
│   └── sealed/            # Sealed secret generation
│       └── sealed.go      # Base64url encoding for secrets
├── examples/              # Example manifests and policies
├── main.go               # Entry point
├── Makefile             # Build automation
└── README.md            # User documentation
```

### Key Design Decisions

#### 1. Configuration Management
- **Choice**: TOML format stored in `~/.kube/coco-config.toml`
- **Rationale**: Human-readable, supports comments, matches CoCo ecosystem
- **Implementation**: Uses `github.com/pelletier/go-toml/v2`

#### 2. Manifest Manipulation
- **Choice**: Generic `map[string]interface{}` approach
- **Rationale**: Flexible, works with any Kubernetes resource type
- **Implementation**: Uses `gopkg.in/yaml.v3` for parsing/serialization
- **Trade-off**: Less type safety, but maximum flexibility

#### 3. InitData Generation
- **Choice**: In-process generation (no external tools)
- **Rationale**: Faster, more portable, easier to maintain
- **Implementation**: Direct gzip + base64 encoding
- **Format**: Matches CoCo spec for aa.toml, cdh.toml, policy.rego

#### 4. Sealed Secrets (Evolution)
- **Initial**: Called external coco-tools via podman/docker
- **Updated**: Direct base64url encoding approach
- **Rationale**: Remove external dependencies, faster execution
- **Format**: `sealed.fakejwsheader.{base64url_json}.fakesignature`

#### 5. Secret Download
- **Choice**: Generate initContainer with curl command
- **Rationale**: Simple, works with CDH, no additional dependencies
- **Implementation**:
  - Convert `kbs://` to CDH endpoint URLs
  - Create emptyDir volume (Memory medium)
  - Mount in both initContainer and app containers

## Implementation Patterns

### 1. Manifest Transformation Pipeline

```go
func transformManifest(m *manifest.Manifest, cfg *config.CocoConfig, rc string) error {
    // 1. Set RuntimeClass
    m.SetRuntimeClass(rc)

    // 2. Add initContainer (if requested)
    if addInitContainer {
        handleInitContainer(m, cfg)
    }

    // 3. Handle secrets (if provided)
    if secretSpec != "" {
        handleSecret(m, secretSpec, cfg)
    }

    // 4. Generate initdata annotation
    initdataValue := initdata.Generate(cfg)
    m.SetAnnotation("io.katacontainers.config.hypervisor.cc_init_data", initdataValue)

    return nil
}
```

### 2. Backup Before Apply

All transformations create a backup file with `-coco` suffix:
```go
backupPath := m.Backup() // app.yaml -> app-coco.yaml
```

### 3. Error Handling

Consistent error wrapping for clear error messages:
```go
if err != nil {
    return fmt.Errorf("failed to load manifest: %w", err)
}
```

### 4. Flag Validation

Validate flag combinations before processing:
```go
if (initContainerImg != "" || initContainerCmd != "") && !addInitContainer {
    return fmt.Errorf("--init-container-img and --init-container-cmd require --init-container flag")
}
```

## Key Features

### 1. Config Creation (`init`)
- Non-interactive mode by default for automation
- Optional interactive mode (--interactive/-i) for prompted configuration
- Validation of mandatory fields (trustee_server)
- Default values for optional fields

### 2. Manifest Apply (`apply`)
- Loads and validates configuration
- Transforms Kubernetes manifests
- Creates backups before modification
- Optional kubectl integration (--skip-apply)

### 3. InitData Generation
- Attestation Agent configuration (aa.toml)
- Confidential Data Hub configuration (cdh.toml)
- Agent policy (policy.rego) - default restrictive
- Gzip compression + base64 encoding
- Proper TOML nesting and structure

### 4. InitContainer Injection
- Default attestation check container
- Custom image support (--init-container-img)
- Custom command support (--init-container-cmd)
- Prepends to existing initContainers

### 5. Secret Download
- Parse `kbs://uri::path` format
- Generate initContainer with curl command
- Create emptyDir volume (Memory medium)
- Mount volume in all containers

### 6. Automatic Secret Addition to Trustee (Temporary)
- Automatically adds K8s secrets to Trustee KBS repository during conversion
- Integrated into the `apply` command secret conversion flow
- Isolated implementation for easy removal when proper tooling is available
- **How it works:**
  - Detects Trustee namespace from the Trustee server URL in config
  - After converting K8s secrets to sealed secrets, automatically copies them to Trustee
  - Uses `kubectl exec` to access the Trustee pod and write secret files
  - Creates directory structure: `/opt/confidential-containers/kbs/repository/{namespace}/{secret-name}/{key}`
- **Implementation details:**
  - Function `AddK8sSecretToTrustee` in `pkg/trustee/trustee.go` (trustee.go:459)
  - Wrapper functions in `cmd/apply.go` (apply.go:351-415):
    - `getTrusteeNamespace`: Extracts namespace from Trustee URL
    - `addSecretsToTrustee`: Iterates over all secrets and adds them
    - `addK8sSecretToTrustee`: Isolated wrapper for easy removal
- **Error handling:**
  - Gracefully handles failures with warnings
  - Continues with manifest transformation even if secret upload fails
  - Provides fallback instructions for manual secret configuration
- **Example:**
  - K8s secret `reg-cred` in namespace `coco` with key `root=password`
  - Stored at: `/opt/confidential-containers/kbs/repository/coco/reg-cred/root`
  - File content: `password` (decoded from base64)

## Testing Strategy

### Manual Testing Approach
Each commit was tested manually:
1. Build: `go build -o kubectl-coco .`
2. Test flags: `./kubectl-coco <command> --help`
3. Test transformation: `./kubectl-coco apply -f examples/pod.yaml --skip-apply`
4. Verify output: Check generated `*-coco.yaml` files
5. Validate YAML: Ensure proper structure and formatting

### Test Cases Covered
- Config creation (non-interactive by default, optional interactive mode)
- Basic manifest transformation
- InitContainer injection (default and custom)
- Secret download with volume mounting
- Flag validation
- Error handling

## Build and Distribution

### Makefile Targets
```makefile
make build      # Build the binary
make install    # Install to /usr/local/bin
make clean      # Remove build artifacts
make test       # Run tests
make help       # Show available targets
```

### Installation
```bash
# From source
make build
sudo make install

# Manual
go build -o kubectl-coco .
sudo mv kubectl-coco /usr/local/bin/
```

## Dependencies

### Direct Dependencies
- `github.com/spf13/cobra` - CLI framework
- `gopkg.in/yaml.v3` - YAML parsing/serialization
- `github.com/pelletier/go-toml/v2` - TOML configuration

### Standard Library Usage
- `encoding/base64` - Base64url encoding for sealed secrets
- `encoding/json` - JSON marshaling for sealed secrets
- `compress/gzip` - InitData compression
- `os/exec` - kubectl integration
- `strings`, `fmt`, `os` - Standard utilities

## Future Enhancements

Potential improvements identified during development:

1. **Kubernetes API Integration**
   - Currently uses `kubectl apply` as subprocess
   - Could use client-go for direct API calls
   - Would enable better error handling and validation

2. **Multi-Manifest Support**
   - Currently processes one manifest at a time
   - Could support multiple files or directories
   - Useful for complex applications

3. **Deployment Support**
   - Currently Pod-focused
   - Could add Deployment, StatefulSet, DaemonSet support
   - Would need to handle pod template specs

4. **Sealed Secret Auto-Creation**
   - Currently requires manual secret creation
   - Could auto-generate and apply K8s secrets
   - Would simplify user workflow

5. **Policy Templates**
   - Provide pre-built policy templates
   - Allow easy policy selection
   - Support policy composition

6. **Testing Framework**
   - Add unit tests for packages
   - Integration tests with test manifests
   - CI/CD pipeline integration

## Lessons Learned

### What Worked Well
1. **Small commits**: Made debugging and review easier
2. **Package separation**: Clear boundaries between concerns
3. **Flag-based approach**: Flexible user experience
4. **Examples directory**: Helpful for testing and documentation

### Challenges Overcome
1. **YAML Manipulation**: Generic maps require careful type assertions
2. **Spec Evolution**: Adapted to changing requirements (--resource-uri → --secret)
3. **External Dependencies**: Moved from coco-tools to native implementation
4. **Volume Management**: Correctly handling volumeMounts across containers

## Contributing Guidelines

For future contributors:

1. **Follow the commit pattern**: Small, focused commits
2. **Update README**: Document new features immediately
3. **Test thoroughly**: Manual testing before commit
4. **Maintain examples**: Add example files for new features
5. **Update this file**: Document architectural decisions

## References

- [Confidential Containers Documentation](https://confidentialcontainers.org/)
- [InitData Feature](https://confidentialcontainers.org/docs/features/initdata/)
- [Sealed Secrets](https://confidentialcontainers.org/docs/features/sealed-secrets/)
- [Get Resource Feature](https://confidentialcontainers.org/docs/features/get-resource/)
- [Cobra CLI Framework](https://cobra.dev/)

## Project Statistics

- **Total Commits**: 11
- **Total Files**: 8 Go files, 1 Makefile, 2 Markdown files
- **Lines of Code**: ~1500 (excluding examples and dependencies)
- **Development Time**: Single session
- **Go Version**: 1.21+

---

*This project was developed with the assistance of Claude Code, demonstrating incremental development with clear git history and comprehensive documentation.*
