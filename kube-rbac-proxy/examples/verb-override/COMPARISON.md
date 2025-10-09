# Comparison: resource-attributes vs verb-override

This document shows the key differences between the standard `resource-attributes` example and the new `verb-override` example.

## Configuration Differences

### Standard resource-attributes example
```yaml
authorization:
  resourceAttributes:
    namespace: default
    apiVersion: v1
    resource: services
    subresource: proxy
    name: kube-rbac-proxy
    # No verb specified - uses HTTP method mapping
```

**Behavior**:
- `GET` request → requires `get` permission on `services/proxy`
- `POST` request → requires `create` permission on `services/proxy`
- `DELETE` request → requires `delete` permission on `services/proxy`

### New verb-override example
```yaml
authorization:
  resourceAttributes:
    namespace: monitoring
    apiVersion: v1
    resource: pods
    verb: "list"  # Static verb override
```

**Behavior**:
- `GET` request → requires `list` permission on `pods`
- `POST` request → requires `list` permission on `pods`
- `DELETE` request → requires `list` permission on `pods`
- **Any HTTP method** → requires `list` permission on `pods`

## RBAC Differences

### Standard resource-attributes client RBAC
```yaml
rules:
- apiGroups: [""]
  resources: ["services/proxy"]
  verbs: ["get"]  # Only GET requests will succeed
```

### Verb-override client RBAC
```yaml
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["list"]  # All HTTP methods will succeed
```

## Use Cases

| Scenario | Standard resource-attributes | Verb-override |
|----------|------------------------------|---------------|
| REST API with standard CRUD operations | ✅ Perfect fit | ❌ Overkill |
| Monitoring endpoints that should always require "list" | ❌ Requires multiple verbs | ✅ Perfect fit |
| Proxy endpoints with non-standard semantics | ❌ HTTP method doesn't match intent | ✅ Explicit verb control |
| Multi-operation endpoints | ❌ Unpredictable permissions | ✅ Consistent permissions |

## When to Use Each

### Use standard resource-attributes when:
- Your API follows standard REST conventions
- HTTP methods accurately represent the Kubernetes operations
- You want different permissions for different HTTP methods
- You're proxying standard Kubernetes API endpoints

### Use verb-override when:
- You want consistent permissions regardless of HTTP method
- Your endpoint semantics don't match HTTP method conventions
- You're building monitoring/metrics endpoints that should always require "list"
- You want to simplify RBAC by using a single verb for all operations

## Security Considerations

### Standard resource-attributes
- **Granular control**: Different HTTP methods can have different permission requirements
- **Principle of least privilege**: Clients only get permissions for operations they actually perform
- **Complexity**: May require multiple RBAC rules for full functionality

### Verb-override
- **Simplified RBAC**: Single verb covers all operations
- **Predictable behavior**: Same authorization check regardless of HTTP method
- **Potential over-permission**: Clients might get broader permissions than strictly necessary

## Migration Path

To migrate from standard resource-attributes to verb-override:

1. **Identify the primary verb** your endpoint should require
2. **Update the configuration** to add the `verb` field
3. **Update client RBAC** to grant the specified verb instead of HTTP method-derived verbs
4. **Test thoroughly** to ensure all expected operations still work
5. **Monitor logs** to verify the correct verb is being checked

Example migration:
```yaml
# Before
authorization:
  resourceAttributes:
    resource: pods
    # GET → "get", POST → "create", etc.

# After
authorization:
  resourceAttributes:
    resource: pods
    verb: "list"  # All methods → "list"
```