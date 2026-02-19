#!/usr/bin/env bash

#
# Makefile with some common workflow for dev, build and test
#

##@ General

# The help target prints out all targets with their descriptions organized
# beneath their categories. The categories are represented by '##@' and the
# target descriptions by '##'. The awk command is responsible for reading the
# entire set of makefiles included in this invocation, looking for lines of the
# file as xyz: ## something, and then pretty-format the target and help. Then,
# if there's a line with ##@ something, that gets pretty-printed as a category.
# More info on the usage of ANSI control characters for terminal formatting:
# https://en.wikipedia.org/wiki/ANSI_escape_code#SGR_parameters
# More info on the awk command:
# http://linuxcommand.org/lc3_adv_awk.php

# The following help command is Licensed under the Apache License, Version 2.0 (the "License")
# Copyright 2023 The Kubernetes Authors.
.PHONY: help
help: ## Display this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)


GO ?= go
GOLANGCILINT ?= golangci-lint

BINARY := kube-auth-proxy
VERSION ?= $(shell cat VERSION 2>/dev/null || echo "undefined")
# Allow to override image registry.
REGISTRY   ?= quay.io/opendatahub
REPOSITORY ?= kube-auth-proxy

DATE := $(shell date +"%Y%m%d")
.NOTPARALLEL:

GO_VERSION = $(shell $(GO) version | cut -c 14- | cut -d' ' -f1 | cut -d'.' -f1-2)
GO_REQUIRED_VERSION = $(shell sed -En 's/^go ([[:digit:]]+\.[[:digit:]]+).*/\1/p' go.mod)
GO_VERSION_VALIDATION_ERR_MSG = Golang version $(GO_VERSION) is not supported, please use Go $(GO_REQUIRED_VERSION)

ifeq ($(COVER),true)
TESTCOVER ?= -coverprofile c.out
endif

##@ Build

.PHONY: build
build: validate-go-version clean $(BINARY) ## Build and create kube-auth-proxy binary from current source code

$(BINARY):
	CGO_ENABLED=0 $(GO) build -a -installsuffix cgo -ldflags="-X github.com/opendatahub-io/kube-auth-proxy/v1/pkg/version.VERSION=${VERSION}" -o $@ github.com/opendatahub-io/kube-auth-proxy/v1

.PHONY: build-fips
build-fips: validate-go-version clean ## Build FIPS-compliant kube-auth-proxy binary
	CGO_ENABLED=1 GOEXPERIMENT=strictfipsruntime $(GO) build -a -tags strictfipsruntime -ldflags="-X github.com/opendatahub-io/kube-auth-proxy/v1/pkg/version.VERSION=${VERSION}" -o $(BINARY) github.com/opendatahub-io/kube-auth-proxy/v1

DOCKERFILE                    ?= Dockerfile.redhat
DOCKER_BUILDX_COMMON_ARGS     ?= --build-arg BUILD_IMAGE=docker.io/library/golang:${GO_REQUIRED_VERSION}-bookworm --build-arg VERSION=${VERSION}

DOCKER_BUILD_PLATFORM         ?= linux/amd64,linux/arm64,linux/ppc64le,linux/s390x
DOCKER_BUILDX                 := docker buildx build ${DOCKER_BUILDX_COMMON_ARGS} -f ${DOCKERFILE} --pull
DOCKER_BUILDX_X_PLATFORM      := $(DOCKER_BUILDX) --platform ${DOCKER_BUILD_PLATFORM}
DOCKER_BUILDX_PUSH            := $(DOCKER_BUILDX) --push
DOCKER_BUILDX_PUSH_X_PLATFORM := $(DOCKER_BUILDX_PUSH) --platform ${DOCKER_BUILD_PLATFORM}

.PHONY: build-docker
build-docker: ## Build multi architecture docker image
	$(DOCKER_BUILDX_X_PLATFORM) -t $(REGISTRY)/$(REPOSITORY):latest -t $(REGISTRY)/$(REPOSITORY):${VERSION} .

.PHONY: build-docker-fips
build-docker-fips: ## Build FIPS-compliant docker image using Dockerfile.redhat
	$(DOCKER_BUILDX_X_PLATFORM) -t $(REGISTRY)/$(REPOSITORY):fips -t $(REGISTRY)/$(REPOSITORY):${VERSION}-fips .

.PHONY: build-docker-all
build-docker-all: build-docker ## Build docker images for all supported architectures
	$(DOCKER_BUILDX) --platform linux/amd64   -t $(REGISTRY)/$(REPOSITORY):latest-amd64   -t $(REGISTRY)/$(REPOSITORY):${VERSION}-amd64 .
	$(DOCKER_BUILDX) --platform linux/arm64   -t $(REGISTRY)/$(REPOSITORY):latest-arm64   -t $(REGISTRY)/$(REPOSITORY):${VERSION}-arm64 .
	$(DOCKER_BUILDX) --platform linux/ppc64le -t $(REGISTRY)/$(REPOSITORY):latest-ppc64le -t $(REGISTRY)/$(REPOSITORY):${VERSION}-ppc64le .
	$(DOCKER_BUILDX) --platform linux/s390x   -t $(REGISTRY)/$(REPOSITORY):latest-s390x -t $(REGISTRY)/$(REPOSITORY):${VERSION}-s390x .


##@ Publish

.PHONY: push-docker
push-docker: ## Push multi architecture docker image
	$(DOCKER_BUILDX_PUSH_X_PLATFORM) -t $(REGISTRY)/$(REPOSITORY):latest -t $(REGISTRY)/$(REPOSITORY):${VERSION} .

.PHONY: push-docker-all
push-docker-all: push-docker ## Push docker images for all supported architectures
	$(DOCKER_BUILDX_PUSH) --platform linux/amd64   -t $(REGISTRY)/$(REPOSITORY):latest-amd64   -t $(REGISTRY)/$(REPOSITORY):${VERSION}-amd64 .
	$(DOCKER_BUILDX_PUSH) --platform linux/arm64   -t $(REGISTRY)/$(REPOSITORY):latest-arm64   -t $(REGISTRY)/$(REPOSITORY):${VERSION}-arm64 .
	$(DOCKER_BUILDX_PUSH) --platform linux/ppc64le -t $(REGISTRY)/$(REPOSITORY):latest-ppc64le -t $(REGISTRY)/$(REPOSITORY):${VERSION}-ppc64le .
	$(DOCKER_BUILDX_PUSH) --platform linux/s390x   -t $(REGISTRY)/$(REPOSITORY):latest-s390x -t $(REGISTRY)/$(REPOSITORY):${VERSION}-s390x .


##@ Nightly scheduling

.PHONY: nightly-build
nightly-build: ## Nightly build command for docker image
	$(DOCKER_BUILDX_X_PLATFORM) -t $(REGISTRY)/$(REPOSITORY)-nightly:latest -t $(REGISTRY)/$(REPOSITORY)-nightly:${DATE} .

.PHONY: nightly-push
nightly-push: ## Nightly push command for docker image
	$(DOCKER_BUILDX_PUSH_X_PLATFORM) -t $(REGISTRY)/$(REPOSITORY)-nightly:latest -t $(REGISTRY)/$(REPOSITORY)-nightly:${DATE} .


##@ Docs

.PHONY: generate
generate: ## Generate alpha config docs from golang structs
	go generate ./pkg/...

.PHONY: verify-generate
verify-generate: generate ## Verify command to check if alpha config docs are in line with golang struct changes
	git diff --exit-code

##@ Miscellaneous

.PHONY: test
test: lint ## Run all Go tests
	GO111MODULE=on $(GO) test $(TESTCOVER) -v -race ./...

.PHONY: test-integration
test-integration: validate-go-version ## Run integration tests
	GO111MODULE=on $(GO) test -tags integration -v -race .
	GO111MODULE=on $(GO) test -v -race ./test/integration/...

.PHONY: release
release: validate-go-version lint test ## Create a full release for all architectures (binaries and checksums)
	BINARY=${BINARY} VERSION=${VERSION} ./dist.sh

.PHONY: clean
clean: ## Cleanup release and build files
	-rm -rf release
	-rm -f $(BINARY)

.PHONY: lint
lint: validate-go-version ## Lint all files using golangci-lint
	GO111MODULE=on $(GOLANGCILINT) run

.PHONY: lint-fix
lint-fix: validate-go-version ## Lint and automatically fix all files using golangci-lint
	GO111MODULE=on $(GOLANGCILINT) run --fix
	GO111MODULE=on $(GOLANGCILINT) fmt

.PHONY: validate-go-version
validate-go-version: ## Validate Go environment requirements
	@if [ "$(GO_VERSION)" != "$(GO_REQUIRED_VERSION)" ]; then \
		echo '$(GO_VERSION_VALIDATION_ERR_MSG)'; \
		exit 1; \
	fi

# local-env can be used to interact with the local development environment
# eg:
#    make local-env-up          # Bring up a basic test environment
#    make local-env-down        # Tear down the basic test environment
#    make local-env-nginx-up    # Bring up an nginx based test environment
#    make local-env-nginx-down  # Tead down the nginx based test environment
.PHONY: local-env-%
local-env-%:
	make -C contrib/local-environment $*
