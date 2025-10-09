# Repository Changes Documentation

## Overview

This document provides a comprehensive overview of all changes made to the `kube-auth-proxy` repository on the current branch (`merge_kube_rbac_proxy`) compared to the `main` branch. The changes introduce significant new functionality, including the integration of `kube-rbac-proxy` and the implementation of a verb override feature for enhanced RBAC authorization control.

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Major Changes](#major-changes)
3. [kube-rbac-proxy Integration](#kube-rbac-proxy-integration)
4. [Verb Override Functionality](#verb-override-functionality)
5. [Combined Container Implementation](#combined-container-implementation)
6. [File Structure Changes](#file-structure-changes)
7. [Docker and Build Changes](#docker-and-build-changes)
8. [Testing and Examples](#testing-and-examples)
9. [Migration Guide](#migration-guide)
10. [Breaking Changes](#breaking-changes)
11. [Future Considerations](#future-considerations)

## Executive Summary

The current branch introduces a major architectural enhancement by:

1. **Integrating kube-rbac-proxy**: Adding the complete kube-rbac-proxy codebase as a subcomponent
2. **Implementing Verb Override**: Adding a new `verb` attribute to `resourceAttributes` configuration
3. **Creating Combined Containers**: Building Docker images that contain both authentication and authorization proxies
4. **Providing Mode Selection**: Implementing an entrypoint system that allows users to choose which proxy to run

These changes transform the repository from a single-purpose OAuth2 authentication proxy into a comprehensive authentication and authorization solution for Kubernetes environments.

## Major Changes

### 1. Repository Structure Enhancement

```
kube-auth-proxy/
├── kube-rbac-proxy/           # NEW: Complete kube-rbac-proxy integration
│   ├── cmd/                   # RBAC proxy command structure
│   ├── pkg/                   # RBAC proxy packages
│   ├── examples/              # RBAC proxy examples
│   └── ...                    # All kube-rbac-proxy files
├── cmd/entrypoint/            # NEW: Mode selection entrypoint
│   └── main.go               # Go-based mode switcher
├── examples/verb-override/    # NEW: Verb override examples
├── Dockerfile.combined        # NEW: Combined container build
├── entrypoint.sh              # Original shell-based entrypoint
└── COMBINED_USAGE.md          # NEW: Usage documentation
```

### 2. Core Functionality Additions

- **Dual Proxy Capability**: Single container can run either authentication or authorization proxy
- **Verb Override**: Static verb configuration for RBAC authorization
- **Enhanced Security**: FIPS-compliant builds with combined functionality
- **Flexible Deployment**: Multiple deployment patterns supported

## kube-rbac-proxy Integration

### Integration Process

The `kube-rbac-proxy` was integrated using **git subtree** to sync from the OpenShift fork rather than using a Git submodule. This approach was chosen to ensure:

1. **Version Control**: Full source code control and modification capability
2. **Custom Modifications**: Ability to implement verb override functionality
3. **Build Integration**: Seamless integration with existing build processes
4. **Unified Documentation**: Consolidated examples and documentation
5. **Git Subtree Benefits**: Maintains clean history while allowing easy synchronization with upstream changes

### Source and Version

- **Source Repository**: `https://github.com/openshift/kube-rbac-proxy`
- **Integration Method**: Git subtree merge
- **Original Upstream**: `github.com/brancz/kube-rbac-proxy` (OpenShift maintains a fork)
- **Version Integrated**: Latest from OpenShift fork at time of integration
- **Integration Date**: Based on commit history
- **Modifications**: Enhanced with verb override functionality

### Git Subtree Integration Details

The integration was performed using git subtree commands to merge the OpenShift kube-rbac-proxy repository:

```bash
# Initial subtree add (example command structure)
git subtree add --prefix=kube-rbac-proxy https://github.com/openshift/kube-rbac-proxy.git main --squash

# Future updates can be pulled using:
git subtree pull --prefix=kube-rbac-proxy https://github.com/openshift/kube-rbac-proxy.git main --squash
```

This approach allows us to:
- Maintain a complete copy of the kube-rbac-proxy code within our repository
- Apply custom modifications for verb override functionality
- Easily sync future updates from the OpenShift fork
- Keep a clean git history with the ability to track our modifications separately

### Key Components Integrated

#### Command Structure
```
kube-rbac-proxy/cmd/kube-rbac-proxy/
├── app/
│   ├── kube-rbac-proxy.go      # Main application logic
│   ├── options/                # Configuration options
│   └── ...
└── main.go                     # Entry point
```

#### Core Packages
```
kube-rbac-proxy/pkg/
├── authz/                      # Authorization logic (MODIFIED)
│   └── auth.go                # Enhanced with verb override
├── proxy/                      # Proxy implementation (MODIFIED)
│   └── proxy.go               # Updated for verb handling
├── authn/                      # Authentication components
└── filters/                    # Request filtering
```

#### Examples and Documentation
```
kube-rbac-proxy/examples/
├── verb-override/              # NEW: Verb override examples
├── resource-attributes/        # Existing examples
└── ...
```

## Verb Override Functionality

### Problem Statement

The original kube-rbac-proxy derived RBAC verbs from HTTP methods:
- `GET` → `get`
- `POST` → `create`
- `PUT` → `update`
- `DELETE` → `delete`

This mapping didn't always align with the desired Kubernetes RBAC permissions, especially for:
- Monitoring endpoints that should always require `list`
- Streaming endpoints that should require `watch`
- Custom APIs with non-standard semantics

### Solution Implementation

#### 1. Configuration Schema Enhancement

**File**: `kube-rbac-proxy/pkg/authz/auth.go`

**Changes**:
```go
// BEFORE
type ResourceAttributes struct {
    Namespace   string `json:"namespace,omitempty"`
    APIGroup    string `json:"apiGroup,omitempty"`
    APIVersion  string `json:"apiVersion,omitempty"`
    Resource    string `json:"resource,omitempty"`
    Subresource string `json:"subresource,omitempty"`
    Name        string `json:"name,omitempty"`
}

// AFTER
type ResourceAttributes struct {
    Namespace   string `json:"namespace,omitempty"`
    APIGroup    string `json:"apiGroup,omitempty"`
    APIVersion  string `json:"apiVersion,omitempty"`
    Resource    string `json:"resource,omitempty"`
    Subresource string `json:"subresource,omitempty"`
    Name        string `json:"name,omitempty"`
    Verb        string `json:"verb,omitempty"`  // NEW: Static verb override
}
```

#### 2. Authorization Logic Update

**File**: `kube-rbac-proxy/pkg/proxy/proxy.go`

**Changes**:
```go
// NEW: Verb override logic in GetRequestAttributes function
func (n krpAuthorizerAttributesGetter) GetRequestAttributes(u user.Info, r *http.Request) []authorizer.Attributes {
    // Derive verb from HTTP method (existing logic)
    apiVerb := "*"
    switch r.Method {
    case "GET": apiVerb = "get"
    case "POST": apiVerb = "create"
    // ... other methods
    }

    // NEW: Override with configured verb if specified
    if n.authzConfig.ResourceAttributes != nil && n.authzConfig.ResourceAttributes.Verb != "" {
        apiVerb = n.authzConfig.ResourceAttributes.Verb
    }

    // Continue with existing logic...
}
```

#### 3. Security Considerations

**Template Support Removed**: Initial implementation included template support for dynamic verb selection, but this was removed for security reasons:

```go
// REJECTED APPROACH (security risk)
verb: "{{ .Value }}"  // Would allow request manipulation

// ACCEPTED APPROACH (secure)
verb: "list"  // Static configuration only
```

### Configuration Examples

#### Static Verb Override
```yaml
authorization:
  resourceAttributes:
    namespace: monitoring
    apiVersion: v1
    resource: pods
    verb: "list"  # Always require "list" regardless of HTTP method
```

#### Combined with Rewrites (Other Attributes)
```yaml
authorization:
  rewrites:
    byQueryParameter:
      name: "namespace"
  resourceAttributes:
    namespace: "{{ .Value }}"  # Templated namespace
    apiVersion: v1
    resource: pods
    verb: "list"              # Static verb (not templated)
```

### Testing Implementation

**File**: `kube-rbac-proxy/pkg/proxy/proxy_test.go`

**Added Test Cases**:
1. `with configured verb in ResourceAttributes`
2. `with different HTTP method but configured verb overrides it`
3. `with configured verb and rewrites - verb is not templated`

## Combined Container Implementation

### Architecture Decision

Rather than requiring separate deployments, the solution provides a unified container with mode selection:

```
┌─────────────────────────────────┐
│        Container Image          │
├─────────────────────────────────┤
│  /bin/entrypoint               │  ← Mode selector
│  /bin/kube-auth-proxy          │  ← OAuth2 authentication
│  /bin/kube-rbac-proxy          │  ← RBAC authorization (enhanced)
│  /etc/ssl/private/jwt_*.pem    │  ← Shared certificates
└─────────────────────────────────┘
```

### Entrypoint Implementation

#### Go-based Entrypoint (`cmd/entrypoint/main.go`)

**Features**:
- Environment variable support (`PROXY_MODE`)
- Command-line argument parsing
- Error handling and validation
- Exec-style process replacement

**Usage**:
```bash
# Command line mode selection
docker run <image> auth [auth-options...]
docker run <image> rbac [rbac-options...]

# Environment variable mode selection
docker run -e PROXY_MODE=auth <image> [options...]
docker run -e PROXY_MODE=rbac <image> [options...]
```

#### Shell-based Entrypoint (`entrypoint.sh`)

**Legacy Support**: Maintained for compatibility and simpler deployments

### Mode Selection Logic

```go
// Priority order:
// 1. Command line argument
// 2. Environment variable (PROXY_MODE)
// 3. Default: "rbac"

mode := "rbac"  // Default

if envMode := os.Getenv("PROXY_MODE"); envMode != "" {
    if envMode == "auth" || envMode == "rbac" {
        mode = envMode
    }
}

if len(args) > 0 && (args[0] == "auth" || args[0] == "rbac") {
    mode = args[0]  // Override environment
    args = args[1:] // Remove mode from arguments
}
```

## File Structure Changes

### New Files Added

#### Core Implementation
- `cmd/entrypoint/main.go` - Go-based mode selection entrypoint
- `entrypoint.sh` - Shell-based mode selection (legacy)
- `Dockerfile.combined` - Combined container build configuration

#### Documentation
- `COMBINED_USAGE.md` - Usage guide for combined containers
- `DOCKERFILE_CHANGES.md` - Docker build changes summary
- `REPOSITORY_CHANGES.md` - This comprehensive documentation

#### Examples
- `examples/verb-override/` - Complete verb override example
  - `README.md` - Detailed usage guide
  - `deployment.yaml` - Kubernetes deployment example
  - `client-rbac.yaml` - Client RBAC configuration
  - `client.yaml` - Test client
  - `test-verb-override.sh` - Automated test script
  - `COMPARISON.md` - Feature comparison guide

#### Complete kube-rbac-proxy Integration
```
kube-rbac-proxy/
├── cmd/kube-rbac-proxy/           # Command structure
├── pkg/                           # Core packages (modified)
├── examples/                      # Examples (enhanced)
├── test/                          # Test suites
├── scripts/                       # Build and utility scripts
├── go.mod, go.sum                 # Go module files
├── Makefile                       # Build configuration
├── Dockerfile                     # Original RBAC proxy Dockerfile
└── README.md, CHANGELOG.md        # Documentation
```

### Modified Files

#### Docker and Build Files
- `Dockerfile` - Enhanced to build both proxies and entrypoint
- `Dockerfile.redhat` - FIPS-compliant combined build
- `Makefile` - Added combined build targets

#### Core kube-rbac-proxy Files (Enhanced)
- `kube-rbac-proxy/pkg/authz/auth.go` - Added verb field to ResourceAttributes
- `kube-rbac-proxy/pkg/proxy/proxy.go` - Implemented verb override logic
- `kube-rbac-proxy/pkg/proxy/proxy_test.go` - Added verb override tests

## Docker and Build Changes

### Dockerfile Enhancements

#### Main Dockerfile Changes
```dockerfile
# BEFORE: Single binary build
RUN GOARCH=${GOARCH} VERSION=${VERSION} make build

COPY --from=builder .../kube-auth-proxy /bin/kube-auth-proxy
ENTRYPOINT ["/bin/kube-auth-proxy"]

# AFTER: Multi-binary build with entrypoint
RUN GOARCH=${GOARCH} VERSION=${VERSION} make build && \
    cd kube-rbac-proxy && GOARCH=${GOARCH} make build && \
    cd .. && CGO_ENABLED=0 GOARCH=${GOARCH} go build -a -installsuffix cgo -o entrypoint ./cmd/entrypoint

COPY --from=builder .../kube-auth-proxy /bin/kube-auth-proxy
COPY --from=builder .../kube-rbac-proxy/_output/kube-rbac-proxy /bin/kube-rbac-proxy
COPY --from=builder .../entrypoint /bin/entrypoint
ENTRYPOINT ["/bin/entrypoint"]
```

#### Dockerfile.redhat FIPS Compliance
```dockerfile
# FIPS-compliant build for kube-auth-proxy
CGO_ENABLED=1 GOOS=linux GOARCH=${GOARCH} GOEXPERIMENT=strictfipsruntime \
go build -a -tags strictfipsruntime \
-ldflags="-X github.com/opendatahub-io/kube-auth-proxy/v1/pkg/version.VERSION=${VERSION}" \
-o kube-auth-proxy github.com/opendatahub-io/kube-auth-proxy/v1

# Standard build for kube-rbac-proxy
cd kube-rbac-proxy && GOARCH=${GOARCH} make build

# Red Hat security hardening
RUN chown 1001:0 /bin/kube-auth-proxy /bin/kube-rbac-proxy /bin/entrypoint && \
    chmod 755 /bin/kube-auth-proxy /bin/kube-rbac-proxy /bin/entrypoint
USER 1001
```

### Makefile Targets

#### New Build Targets
```makefile
##@ Combined Proxy

.PHONY: build-combined
build-combined: ## Build combined docker image with both proxies
	$(DOCKER_BUILDX) -f Dockerfile.combined -t $(REGISTRY)/$(REPOSITORY):combined

.PHONY: build-combined-multi
build-combined-multi: ## Build multi architecture combined docker image
	$(DOCKER_BUILDX_X_PLATFORM) -f Dockerfile.combined -t $(REGISTRY)/$(REPOSITORY):combined
```

#### Enhanced FIPS Target
```makefile
.PHONY: build-docker-fips
build-docker-fips: ## Build FIPS-compliant combined docker image
	$(DOCKER_BUILDX_X_PLATFORM) -f Dockerfile.redhat -t $(REGISTRY)/$(REPOSITORY):fips
```

## Testing and Examples

### Comprehensive Example: verb-override

#### Directory Structure
```
examples/verb-override/
├── README.md              # Comprehensive usage guide
├── deployment.yaml        # Complete Kubernetes deployment
├── client-rbac.yaml       # Client RBAC with "list" permission
├── client.yaml            # Test client job
├── test-verb-override.sh  # Automated test script
└── COMPARISON.md          # Feature comparison guide
```

#### Key Test Scenarios

1. **Static Verb Configuration**
   ```yaml
   resourceAttributes:
     namespace: monitoring
     resource: pods
     verb: "list"  # Always require "list"
   ```

2. **HTTP Method Override Verification**
   ```bash
   # Both should require "list" permission
   curl -X GET  <endpoint>  # Normally "get" → now "list"
   curl -X POST <endpoint>  # Normally "create" → now "list"
   ```

3. **Security Validation**
   ```bash
   # Should fail with wrong permissions
   # Client has only "get" permission, needs "list"
   ```

#### Automated Testing

**File**: `examples/verb-override/test-verb-override.sh`

**Test Flow**:
1. Deploy kube-rbac-proxy with verb override
2. Deploy client RBAC with correct permissions
3. Test GET request (should succeed)
4. Test POST request (should succeed - same verb)
5. Change RBAC to wrong permission (should fail)
6. Restore correct permissions
7. Validate proxy logs show correct verb usage

### Test Coverage

#### Unit Tests
- `kube-rbac-proxy/pkg/proxy/proxy_test.go`: 11 test cases
- New verb override scenarios: 3 additional test cases
- All existing functionality: Regression tested

#### Integration Tests
- Verb override example deployment
- Combined container functionality
- Mode selection validation

## Migration Guide

### For Existing kube-auth-proxy Users

#### No Breaking Changes
Existing deployments continue to work without modification:

```yaml
# BEFORE & AFTER: Works identically
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
      - name: kube-auth-proxy
        image: quay.io/opendatahub/kube-auth-proxy:latest
        args:
        - "--upstream=http://127.0.0.1:8080/"
        - "--http-address=0.0.0.0:4180"
```

#### Optional: Leverage New Functionality
```yaml
# NEW: Use combined container with mode selection
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
      - name: auth-proxy
        image: quay.io/opendatahub/kube-auth-proxy:latest
        command: ["/bin/entrypoint", "auth"]  # Explicit mode
        args:
        - "--upstream=http://127.0.0.1:8080/"
        - "--http-address=0.0.0.0:4180"
```

### For New RBAC Authorization Users

#### Basic RBAC Proxy Usage
```yaml
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
      - name: rbac-proxy
        image: quay.io/opendatahub/kube-auth-proxy:latest
        command: ["/bin/entrypoint", "rbac"]
        args:
        - "--secure-listen-address=0.0.0.0:8443"
        - "--upstream=http://127.0.0.1:8080/"
        - "--config-file=/etc/config/auth.yaml"
```

#### Verb Override Configuration
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: rbac-config
data:
  auth.yaml: |
    authorization:
      resourceAttributes:
        namespace: monitoring
        apiVersion: v1
        resource: pods
        verb: "list"  # Override HTTP method mapping
```

### Migration Steps

1. **Assessment Phase**
   - Review current authentication/authorization needs
   - Identify endpoints that would benefit from verb override
   - Plan RBAC permission structure

2. **Gradual Migration**
   - Option A: Keep existing auth-only deployments
   - Option B: Migrate to combined containers with explicit modes
   - Option C: Add RBAC authorization to existing deployments

3. **Validation**
   - Test new functionality in development environments
   - Validate RBAC permissions work as expected
   - Verify backward compatibility

## Breaking Changes

### None for Existing Users

The implementation was designed with backward compatibility as a primary concern:

- **Default Behavior**: Unchanged for kube-auth-proxy functionality
- **Configuration**: All existing configurations remain valid
- **API**: No changes to existing command-line arguments or configuration files
- **Deployment**: Existing deployment manifests work without modification

### New Requirements (Optional)

#### For RBAC Functionality
- Kubernetes cluster with RBAC enabled
- ServiceAccount with appropriate permissions:
  ```yaml
  rules:
  - apiGroups: ["authorization.k8s.io"]
    resources: ["subjectaccessreviews"]
    verbs: ["create"]
  ```

#### For Verb Override
- Client RBAC permissions must match configured verbs:
  ```yaml
  # If verb: "list" is configured
  rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["list"]  # Must match configured verb
  ```

## Future Considerations

### Planned Enhancements

1. **Extended Verb Support**
   - Consider additional RBAC verb mappings
   - Evaluate custom verb definitions

2. **Enhanced Mode Selection**
   - Configuration-driven mode selection
   - Runtime mode switching capabilities

3. **Monitoring and Observability**
   - Metrics for verb override usage
   - Enhanced logging for authorization decisions

4. **Security Hardening**
   - Additional FIPS compliance validation
   - Security scanning integration

### Potential Extensions

1. **Multi-tenant Support**
   - Namespace-aware configurations
   - Tenant-specific verb mappings

2. **Integration Improvements**
   - Helm chart for simplified deployment
   - Operator pattern for configuration management

3. **Performance Optimization**
   - Caching for authorization decisions
   - Optimized binary sizes

### Deprecation Policy

- **Shell Entrypoint**: `entrypoint.sh` may be deprecated in favor of Go binary
- **Legacy Configuration**: Old configuration patterns will be supported indefinitely
- **Build Targets**: Separate build targets may be consolidated

## Conclusion

The changes implemented in this branch represent a significant evolution of the kube-auth-proxy project:

1. **Scope Expansion**: From authentication-only to authentication + authorization
2. **Enhanced Security**: Verb override provides more precise RBAC control
3. **Deployment Flexibility**: Combined containers with mode selection
4. **Backward Compatibility**: Zero breaking changes for existing users
5. **Enterprise Ready**: FIPS-compliant builds for regulated environments

The implementation maintains the project's core principles while expanding its capabilities to address broader Kubernetes security requirements. The verb override functionality specifically addresses real-world scenarios where HTTP method mapping to RBAC verbs doesn't align with security policies.

These changes position kube-auth-proxy as a comprehensive solution for Kubernetes authentication and authorization proxy requirements, suitable for both simple authentication scenarios and complex enterprise security architectures.