# verb-override example

> Note to try this out with minikube, make sure you enable RBAC correctly as explained [here](../minikube-rbac).

This example demonstrates the new `verb` attribute in `resourceAttributes` configuration. The verb attribute allows you to specify a static custom verb that overrides the HTTP method-derived verb for RBAC authorization checks.

## Use Case

In this example, we deploy a [prometheus-example-app](https://github.com/brancz/prometheus-example-app) and protect it with the kube-rbac-proxy. Instead of using the default HTTP method mapping (GET → `get`), we configure the proxy to always require `list` permissions on pods in the monitoring namespace, regardless of the HTTP method used.

This is useful when:
- Your API endpoint should always require the same RBAC permission regardless of HTTP method
- You want to standardize on specific verbs like `list` for monitoring endpoints
- The HTTP method doesn't accurately represent the Kubernetes operation being performed

## Configuration

The key difference from the standard resource-attributes example is the addition of the `verb: "list"` field in the resourceAttributes configuration:

```yaml
authorization:
  resourceAttributes:
    namespace: monitoring
    apiGroup: ""
    apiVersion: v1
    resource: pods
    verb: "list"  # Override: always require "list" permission instead of HTTP method-derived verb
```

With this configuration:
- A `GET` request would normally require `get` permission, but now requires `list`
- A `POST` request would normally require `create` permission, but now requires `list`
- Any HTTP method will require `list` permission on pods in the monitoring namespace

## Deployment

The kube-rbac-proxy itself requires RBAC access to perform TokenReviews and SubjectAccessReviews. These are the APIs available from the Kubernetes API to authenticate and then validate the authorization of an entity.

```bash
$ kubectl create -f deployment.yaml
```

The content of this manifest is:

[embedmd]:# (./deployment.yaml)
```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: kube-rbac-proxy-verb-override
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: kube-rbac-proxy-verb-override
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: kube-rbac-proxy-verb-override
subjects:
- kind: ServiceAccount
  name: kube-rbac-proxy-verb-override
  namespace: default
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: kube-rbac-proxy-verb-override
rules:
- apiGroups: ["authentication.k8s.io"]
  resources:
  - tokenreviews
  verbs: ["create"]
- apiGroups: ["authorization.k8s.io"]
  resources:
  - subjectaccessreviews
  verbs: ["create"]
---
apiVersion: v1
kind: Service
metadata:
  labels:
    app: kube-rbac-proxy-verb-override
  name: kube-rbac-proxy-verb-override
spec:
  ports:
  - name: https
    port: 8443
    targetPort: https
  selector:
    app: kube-rbac-proxy-verb-override
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: kube-rbac-proxy-verb-override
data:
  config-file.yaml: |+
    authorization:
      resourceAttributes:
        namespace: monitoring
        apiVersion: v1
        resource: pods
        verb: "list"
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: kube-rbac-proxy-verb-override
spec:
  replicas: 1
  selector:
    matchLabels:
      app: kube-rbac-proxy-verb-override
  template:
    metadata:
      labels:
        app: kube-rbac-proxy-verb-override
    spec:
      securityContext:
        runAsUser: 65532
      serviceAccountName: kube-rbac-proxy-verb-override
      containers:
      - name: kube-rbac-proxy
        image: quay.io/brancz/kube-rbac-proxy:v0.19.1
        args:
        - "--secure-listen-address=0.0.0.0:8443"
        - "--upstream=http://127.0.0.1:8081/"
        - "--config-file=/etc/kube-rbac-proxy/config-file.yaml"
        - "--logtostderr=true"
        - "--v=10"
        ports:
        - containerPort: 8443
          name: https
        volumeMounts:
        - name: config
          mountPath: /etc/kube-rbac-proxy
        securityContext:
          allowPrivilegeEscalation: false
      - name: prometheus-example-app
        image: quay.io/brancz/prometheus-example-app:v0.5.0
        args:
        - "--bind=127.0.0.1:8081"
      volumes:
      - name: config
        configMap:
          name: kube-rbac-proxy-verb-override
```

## Testing

Once the prometheus-example-app is up and running, we can test it. In order to test it, we deploy a Job that performs a `curl` against the above deployment.

**Important**: Notice that the client RBAC now requires `list` permission on pods instead of the usual `get` permission on services/proxy. This demonstrates that the verb override is working.

```bash
$ kubectl create -f client-rbac.yaml client.yaml
```

The content of these manifests are:

[embedmd]:# (./client-rbac.yaml)
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: kube-rbac-proxy-verb-override-client
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["list"]  # Note: "list" permission required, not "get"
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: kube-rbac-proxy-verb-override-client
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: kube-rbac-proxy-verb-override-client
subjects:
- kind: ServiceAccount
  name: default
  namespace: default
```

[embedmd]:# (./client.yaml)
```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: krp-curl-verb-override
spec:
  template:
    metadata:
      name: krp-curl-verb-override
    spec:
      containers:
      - name: krp-curl
        image: quay.io/brancz/krp-curl:v0.0.2
        env:
        - name: SERVICE_URL
          value: "https://kube-rbac-proxy-verb-override.default.svc:8443"
      restartPolicy: Never
  backoffLimit: 4
```

## Testing Different HTTP Methods

To verify that the verb override is working correctly, you can test with different HTTP methods. All should require the same `list` permission:

```bash
# Test GET request (normally requires "get", now requires "list")
kubectl exec -it <pod-name> -- curl -k -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" https://kube-rbac-proxy-verb-override.default.svc:8443/metrics

# Test POST request (normally requires "create", now requires "list")
kubectl exec -it <pod-name> -- curl -X POST -k -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" https://kube-rbac-proxy-verb-override.default.svc:8443/metrics
```

Both requests will succeed because they both require `list` permission on pods, which the client has been granted.

## Verification

You can verify the configuration is working by:

1. **Checking logs**: The kube-rbac-proxy logs (with `-v=10`) will show the authorization decisions
2. **Testing with wrong permissions**: Try removing `list` permission and adding only `get` permission - requests should fail
3. **Testing different HTTP methods**: All HTTP methods should require the same `list` permission

The logs should show something like:
```
I1206 10:30:00.123456       1 proxy.go:67] kube-rbac-proxy request attributes: attrs=authz.AttributesRecord{User:(*user.DefaultInfo)(0x...), Verb:"list", Namespace:"monitoring", APIGroup:"", APIVersion:"v1", Resource:"pods", ...}
```

Notice that the verb is "list" regardless of the HTTP method used in the request.