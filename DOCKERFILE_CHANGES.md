# Dockerfile Changes Summary

This document summarizes the changes made to both Dockerfile and Dockerfile.redhat to support the combined proxy functionality with verb override capability.

## Changes Applied to Both Dockerfiles

### 1. **Dependency Setup**
- Added kube-rbac-proxy dependency download step
- Both main application and kube-rbac-proxy dependencies are now fetched

### 2. **Build Process**
- **Main Dockerfile**: Uses `make build` for kube-auth-proxy and `make build` for kube-rbac-proxy
- **Dockerfile.redhat**: Uses direct `go build` with FIPS compliance for kube-auth-proxy and `make build` for kube-rbac-proxy
- Added entrypoint binary compilation for mode selection

### 3. **Binary Copying**
Now copies three binaries:
- `/bin/kube-auth-proxy` - OAuth2 authentication proxy
- `/bin/kube-rbac-proxy` - RBAC authorization proxy (with verb override functionality)
- `/bin/entrypoint` - Mode selection wrapper

### 4. **Entrypoint Changes**
- **Before**: `ENTRYPOINT ["/bin/kube-auth-proxy"]`
- **After**: `ENTRYPOINT ["/bin/entrypoint"]`

### 5. **Labels Updated**
- Description updated to reflect combined functionality
- Title changed to indicate combined proxy capabilities

## Key Differences Between Dockerfiles

| Aspect | Dockerfile | Dockerfile.redhat |
|--------|------------|-------------------|
| Base Image | Configurable via BUILD_IMAGE | registry.access.redhat.com/ubi9/go-toolset |
| Runtime Image | Configurable via RUNTIME_IMAGE | registry.access.redhat.com/ubi9/ubi-minimal |
| kube-auth-proxy Build | `make build` | Direct `go build` with FIPS compliance |
| kube-rbac-proxy Build | `make build` | `make build` |
| Security | Standard | FIPS-compliant with strictfipsruntime |
| User | Default (varies by runtime image) | 1001 (non-root) |
| Permissions | Standard | Explicit chown/chmod for security |

## Usage

Both Dockerfiles now support mode selection through the entrypoint:

```bash
# Run as OAuth2 authentication proxy (default for auth mode)
docker run <image> auth [auth-options...]

# Run as RBAC authorization proxy (default mode)
docker run <image> rbac [rbac-options...]

# Or use environment variable
docker run -e PROXY_MODE=auth <image> [options...]
```

## Build Commands

```bash
# Standard build
make build-docker

# FIPS-compliant build
make build-docker-fips

# Combined build
make build-combined
```

## New Functionality

The kube-rbac-proxy now includes verb override functionality:
- Configure static verbs in resourceAttributes
- Override HTTP method-derived verbs
- Secure static-only configuration (no templating for security)

Example configuration:
```yaml
authorization:
  resourceAttributes:
    namespace: monitoring
    resource: pods
    verb: "list"  # Always require "list" regardless of HTTP method
```