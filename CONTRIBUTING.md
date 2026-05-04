# Contributing

To develop on this project, please fork the repo and clone it locally.

## Development Setup

### Prerequisites

- Go (version specified in `go.mod`)
- golangci-lint
- Docker with buildx (for container builds)
- pre-commit (`pipx install pre-commit && pre-commit install`)

### Build

```bash
make build          # Build the kube-auth-proxy binary
make build-fips     # Build FIPS-compliant binary
```

### Test

```bash
make test               # Run lint + all tests with race detection
make test-integration   # Run integration tests only
COVER=true make test    # Run tests with coverage
```

### Lint

```bash
make lint       # Run golangci-lint
make lint-fix   # Auto-fix lint issues
```

### Code Generation

```bash
make verify-generate    # Verify generated code is up to date
```

## Pull Requests and Issues

We track bugs and issues using Github.

If you find a bug, please open an Issue.

If you want to fix a bug, please fork, create a feature branch, fix the bug and
open a PR back to this repo.
Please mention the open bug issue number within your PR if applicable.
