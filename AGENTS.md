# kube-auth-proxy Agent Guidelines

## Project Overview

Authentication proxy for OpenShift AI (RHOAI) that handles both external OIDC providers and OpenShift's internal OAuth service. FIPS-compliant. Includes `kube-rbac-proxy` as a subproject under `kube-rbac-proxy/`.

## Architecture

```text
cmd/                - CLI entry point (not used directly, main.go is root-level)
pkg/                - Core packages (apis, encryption, options, version)
providers/          - Authentication provider implementations (OIDC, OpenShift OAuth)
kube-rbac-proxy/    - Embedded kube-rbac-proxy subproject (separate go.mod)
contrib/            - Deployment manifests
examples/           - Example configurations
docs/               - Docusaurus documentation site
```

Main entry point is `main.go` at repo root. OAuth proxy logic is in `oauthproxy.go`.

## Build and Run

```bash
make build              # Build kube-auth-proxy binary
make build-fips         # Build FIPS-compliant binary
make build-docker       # Build multi-arch docker image
make test               # Run lint + all tests
make test-integration   # Run integration tests only
make lint               # Run golangci-lint
make lint-fix           # Auto-fix lint issues
make clean              # Remove built binary
make verify-generate    # Verify code generation is up to date
```

## Test Guidelines

- Tests use standard Go testing (`go test`)
- Integration tests use build tag `integration`
- Test files: `*_test.go` at repo root and in packages
- Coverage enabled via `COVER=true` environment variable
- CI uses Code Climate for coverage reporting

## Debug and Troubleshooting

- Run `make lint` first for any code issues
- For test failures: `go test -v -race ./...`
- For integration tests: `go test -tags integration -v -race .`
- Check `.golangci.yml` for linter configuration
- DESIGN.md contains full architecture and requirements documentation
