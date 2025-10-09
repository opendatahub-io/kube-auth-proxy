# Quick Reference Guide

## TL;DR

This repository now provides both **authentication** (OAuth2) and **authorization** (RBAC) proxy functionality in a single container image with a new **verb override** feature.

## What's New

### 🔄 Combined Container
- Single image contains both `kube-auth-proxy` and `kube-rbac-proxy`
- Choose mode at runtime: `auth` or `rbac`

### 🎯 Verb Override
- Configure static RBAC verbs instead of HTTP method mapping
- Example: All requests require `list` permission regardless of GET/POST/DELETE

### 🔒 Enhanced Security
- FIPS-compliant builds available
- Static-only verb configuration (no request manipulation)

## Quick Start

### Authentication Proxy (OAuth2)
```bash
# Same as before - no changes
docker run <image> auth --upstream=http://127.0.0.1:8080/ --http-address=0.0.0.0:4180
```

### Authorization Proxy (RBAC)
```bash
# New functionality
docker run <image> rbac --secure-listen-address=0.0.0.0:8443 --upstream=http://127.0.0.1:8080/
```

### Authorization with Verb Override
```yaml
# config.yaml
authorization:
  resourceAttributes:
    namespace: monitoring
    resource: pods
    verb: "list"  # Always require "list" permission
```

```bash
docker run -v $(pwd)/config.yaml:/config.yaml <image> rbac --config-file=/config.yaml
```

## Verb Override Examples

### Standard Behavior (Before)
```yaml
resourceAttributes:
  resource: pods
# GET request    → requires "get" permission
# POST request   → requires "create" permission
# DELETE request → requires "delete" permission
```

### With Verb Override (New)
```yaml
resourceAttributes:
  resource: pods
  verb: "list"
# ANY request → requires "list" permission
```

## Migration Checklist

### ✅ Existing Users (No Action Required)
- [x] All existing configurations work unchanged
- [x] Same container images and deployment patterns
- [x] Zero breaking changes

### 🆕 New RBAC Users
- [ ] Design RBAC permission structure
- [ ] Create ServiceAccount with SubjectAccessReview permissions
- [ ] Configure resourceAttributes with appropriate verbs
- [ ] Test authorization with different HTTP methods

## Common Use Cases

### Monitoring Endpoints
```yaml
# Always require "list" for metrics endpoints
resourceAttributes:
  namespace: monitoring
  resource: pods
  verb: "list"
```

### API Gateways
```yaml
# Custom verb for non-standard endpoints
resourceAttributes:
  namespace: api
  resource: services
  verb: "watch"
```

### Multi-operation Endpoints
```yaml
# Consistent permission for complex operations
resourceAttributes:
  namespace: app
  resource: configmaps
  verb: "get"  # Simplified permission model
```

## Build Targets

```bash
# Standard combined image
make build-combined

# FIPS-compliant combined image
make build-docker-fips

# Multi-architecture build
make build-combined-multi
```

## Troubleshooting

### Mode Selection Issues
```bash
# Check entrypoint logs
kubectl logs <pod> | grep "Starting"

# Expected output:
# Starting kube-auth-proxy...  (auth mode)
# Starting kube-rbac-proxy... (rbac mode)
```

### Verb Override Not Working
```bash
# Check RBAC proxy logs with verbose logging
kubectl logs <pod> -c rbac-proxy
# Look for: Verb:"list" in authorization attributes
```

### Permission Denied (403)
```bash
# Check client RBAC matches configured verb
kubectl auth can-i list pods --as=system:serviceaccount:default:default

# Should match the configured verb in resourceAttributes
```

## Examples Repository

| Example | Location | Purpose |
|---------|----------|---------|
| Basic Auth | Original examples | OAuth2 authentication |
| Basic RBAC | `kube-rbac-proxy/examples/` | Standard RBAC authorization |
| Verb Override | `examples/verb-override/` | Static verb configuration |
| Combined Usage | `COMBINED_USAGE.md` | Mode selection patterns |

## Support and Documentation

- **Full Documentation**: `REPOSITORY_CHANGES.md`
- **Technical Details**: `TECHNICAL_IMPLEMENTATION.md`
- **Docker Changes**: `DOCKERFILE_CHANGES.md`
- **Combined Usage**: `COMBINED_USAGE.md`
- **Verb Override Example**: `examples/verb-override/README.md`

## Need Help?

1. Check existing examples in `examples/verb-override/`
2. Run test script: `examples/verb-override/test-verb-override.sh`
3. Review logs with verbose output (`-v=10`)
4. Validate RBAC permissions with `kubectl auth can-i`