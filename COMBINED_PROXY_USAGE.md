# Combined Kube-Auth-Proxy and Kube-RBAC-Proxy Container

This container image includes both `kube-auth-proxy` and `kube-rbac-proxy` binaries, allowing you to select which proxy to run using either an environment variable or a command line argument.

## Usage

The container supports two ways to specify the proxy mode:

1. **Environment Variable**: Set `PROXY_MODE` environment variable to `auth` or `rbac`
2. **Command Line Argument**: Pass `auth` or `rbac` as the first argument (overrides environment variable)

**Default Mode**: If neither environment variable nor command line argument is specified, the container runs in `rbac` mode.

### Running kube-rbac-proxy (default)

```bash
# Default mode - runs kube-rbac-proxy
docker run kube-combined-proxy:latest [rbac-proxy-arguments...]

# Explicit rbac mode via command line
docker run kube-combined-proxy:latest rbac [rbac-proxy-arguments...]

# Explicit rbac mode via environment variable
docker run -e PROXY_MODE=rbac kube-combined-proxy:latest [rbac-proxy-arguments...]
```

### Running kube-auth-proxy

```bash
# Auth mode via command line
docker run kube-combined-proxy:latest auth [auth-proxy-arguments...]

# Auth mode via environment variable
docker run -e PROXY_MODE=auth kube-combined-proxy:latest [auth-proxy-arguments...]
```

## Examples

### Kube-RBAC-Proxy Examples (Default Mode)

```bash
# Get version (default mode - rbac)
docker run kube-combined-proxy:latest --version

# Get version (explicit rbac mode via command line)
docker run kube-combined-proxy:latest rbac --version

# Get version (explicit rbac mode via environment variable)
docker run -e PROXY_MODE=rbac kube-combined-proxy:latest --version

# Run with configuration
docker run kube-combined-proxy:latest --upstream=http://127.0.0.1:8080 --logtostderr=true
```

### Kube-Auth-Proxy Examples

```bash
# Get version (auth mode via command line)
docker run kube-combined-proxy:latest auth --version

# Get version (auth mode via environment variable)
docker run -e PROXY_MODE=auth kube-combined-proxy:latest --version

# Run with configuration (environment variable approach)
docker run -v /path/to/config:/config -e PROXY_MODE=auth kube-combined-proxy:latest --config=/config/oauth2_proxy.cfg

# Run with configuration (command line approach)
docker run -v /path/to/config:/config kube-combined-proxy:latest auth --config=/config/oauth2_proxy.cfg
```

### Mode Override Examples

```bash
# Environment variable set to rbac, but command line overrides to auth
docker run -e PROXY_MODE=rbac kube-combined-proxy:latest auth --version
# Output: Starting kube-auth-proxy...

# Environment variable set to auth, but command line overrides to rbac
docker run -e PROXY_MODE=auth kube-combined-proxy:latest rbac --version
# Output: Starting kube-rbac-proxy...
```

## Kubernetes Deployment Examples

### RBAC Proxy Deployment (Default Mode)

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: rbac-proxy
spec:
  replicas: 1
  selector:
    matchLabels:
      app: rbac-proxy
  template:
    metadata:
      labels:
        app: rbac-proxy
    spec:
      containers:
      - name: rbac-proxy
        image: kube-combined-proxy:latest
        # No PROXY_MODE needed - defaults to rbac
        args:
          - "--upstream=http://127.0.0.1:8080/"
          - "--logtostderr=true"
          # Add other rbac proxy arguments here
```

### Auth Proxy Deployment (Using Environment Variable)

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: auth-proxy
spec:
  replicas: 1
  selector:
    matchLabels:
      app: auth-proxy
  template:
    metadata:
      labels:
        app: auth-proxy
    spec:
      containers:
      - name: auth-proxy
        image: kube-combined-proxy:latest
        env:
        - name: PROXY_MODE
          value: "auth"
        args:
          - "--upstream=http://backend-service:8080"
          - "--http-address=0.0.0.0:4180"
          # Add other auth proxy arguments here
```

### Auth Proxy Deployment (Using Command Line)

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: auth-proxy-cli
spec:
  replicas: 1
  selector:
    matchLabels:
      app: auth-proxy-cli
  template:
    metadata:
      labels:
        app: auth-proxy-cli
    spec:
      containers:
      - name: auth-proxy
        image: kube-combined-proxy:latest
        args:
          - "auth"
          - "--upstream=http://backend-service:8080"
          - "--http-address=0.0.0.0:4180"
          # Add other auth proxy arguments here
```

## Error Handling

### Invalid Command Line Mode

If an invalid mode is specified via command line (not "auth" or "rbac"), the container will exit with an error:

```bash
$ docker run kube-combined-proxy:latest invalid-mode
Invalid mode: invalid-mode
Usage: /bin/entrypoint [auth|rbac] [additional arguments...]
Mode can also be set with PROXY_MODE environment variable
  auth - Run kube-auth-proxy
  rbac - Run kube-rbac-proxy (default)
```

### Invalid Environment Variable

If an invalid `PROXY_MODE` environment variable is set, the container will exit with an error:

```bash
$ docker run -e PROXY_MODE=invalid kube-combined-proxy:latest
Invalid PROXY_MODE environment variable: invalid
PROXY_MODE must be 'auth' or 'rbac'
```

## Mode Selection Priority

The mode selection follows this priority order:

1. **Command Line Argument** (highest priority) - overrides everything
2. **PROXY_MODE Environment Variable** (medium priority) - used if no command line mode specified
3. **Default Mode** (lowest priority) - `rbac` mode if neither above is specified

## Building the Image

To build the combined image:

```bash
docker build \
  --build-arg BUILD_IMAGE=docker.io/library/golang:1.24-bookworm \
  --build-arg RUNTIME_IMAGE=gcr.io/distroless/static:nonroot \
  --build-arg VERSION=v1.0.0 \
  -t kube-combined-proxy:v1.0.0 .
```

## Architecture

The container includes:
- `/bin/kube-auth-proxy` - The OAuth2 authentication proxy
- `/bin/kube-rbac-proxy` - The Kubernetes RBAC authorization proxy
- `/bin/entrypoint` - A Go-based entrypoint that routes to the correct binary based on the mode parameter

Both binaries are built from their respective source code and included in a distroless runtime image for security and minimal size.