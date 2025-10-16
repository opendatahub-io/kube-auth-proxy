# The image ARGs have to be at the top, otherwise the docker daemon cannot validate
# the FROM statements and overall Dockerfile
#
# Argument for setting the build image
ARG BUILD_IMAGE=placeholder
# Argument for setting the runtime image
ARG RUNTIME_IMAGE=placeholder
# Argument for setting the oauth2-proxy build version
ARG VERSION

# All builds should be done using the platform native to the build node to allow
#  cache sharing of the go mod download step.
# Go cross compilation is also faster than emulation the go compilation across
#  multiple platforms.
FROM --platform=${BUILDPLATFORM} ${BUILD_IMAGE} AS builder

# Switch to root for build permissions
USER root

# Copy sources
WORKDIR /workspace

# Fetch dependencies for main application
COPY go.mod go.sum ./
RUN go mod download

# Now pull in our code
COPY . .

# Setup kube-rbac-proxy dependencies
WORKDIR /workspace/kube-rbac-proxy
RUN go mod download

# Go back to main workdir
WORKDIR /workspace

# Arguments go here so that the previous steps can be cached if no external sources
# have changed. These arguments are automatically set by the docker engine.
ARG TARGETPLATFORM
ARG BUILDPLATFORM

# Reload version argument
ARG VERSION

# Build all binaries and make sure there is at least an empty key file.
#  This is useful for GCP App Engine custom runtime builds, because
#  you cannot use multiline variables in their app.yaml, so you have to
#  build the key into the container and then tell it where it is
#  by setting OAUTH2_PROXY_JWT_KEY_FILE=/etc/ssl/private/jwt_signing_key.pem
#  in app.yaml instead.
# Set the cross compilation arguments based on the TARGETPLATFORM which is
#  automatically set by the docker engine.
RUN case ${TARGETPLATFORM} in \
         "linux/amd64")  GOARCH=amd64  ;; \
         # arm64 and arm64v8 are equivalent in go and do not require a goarm
         # https://github.com/golang/go/wiki/GoArm
         "linux/arm64" | "linux/arm/v8")  GOARCH=arm64  ;; \
         "linux/ppc64le")  GOARCH=ppc64le  ;; \
         "linux/s390x")  GOARCH=s390x  ;; \
         "linux/arm/v6") GOARCH=arm GOARM=6  ;; \
         "linux/arm/v7") GOARCH=arm GOARM=7 ;; \
    esac && \
    printf "Building OAuth2 Proxy for arch ${GOARCH}\n" && \
    GOARCH=${GOARCH} VERSION=${VERSION} make build && touch jwt_signing_key.pem && \
    printf "Building kube-rbac-proxy for arch ${GOARCH}\n" && \
    VERSION_SEMVER=$(echo "${VERSION}" | grep -o 'v[0-9]\+\.[0-9]\+\.[0-9]\+' || echo "v0.19.1") && \
    cd kube-rbac-proxy && GOARCH=${GOARCH} VERSION="${VERSION}" VERSION_SEMVER="${VERSION_SEMVER}" make build && \
    cd .. && printf "Building entrypoint for arch ${GOARCH}\n" && \
    CGO_ENABLED=0 GOARCH=${GOARCH} go build -a -installsuffix cgo -o entrypoint ./cmd/entrypoint

# Reload runtime image
ARG RUNTIME_IMAGE
# Copy binary to runtime image
FROM ${RUNTIME_IMAGE}
# Reload version
ARG VERSION

COPY --from=builder /workspace/kube-auth-proxy /bin/kube-auth-proxy
COPY --from=builder /workspace/kube-rbac-proxy/_output/kube-rbac-proxy /bin/kube-rbac-proxy
COPY --chown=1001:0 --from=builder /workspace/jwt_signing_key.pem /etc/ssl/private/jwt_signing_key.pem
COPY --from=builder /workspace/entrypoint /bin/entrypoint

# Set proper permissions for non-root execution
RUN chown -R 1001:0 /etc/ssl/private && \
    chmod -R g=u /etc/ssl/private && \
    chown 1001:0 /bin/kube-auth-proxy /bin/kube-rbac-proxy /bin/entrypoint && \
    chmod 755 /bin/kube-auth-proxy /bin/kube-rbac-proxy /bin/entrypoint

USER 1001

LABEL org.opencontainers.image.licenses=MIT \
      org.opencontainers.image.description="A reverse proxy that provides authentication with Google, Azure, OpenID Connect and many more identity providers." \
      org.opencontainers.image.documentation=https://github.com/opendatahub-io/kube-auth-proxy \
      org.opencontainers.image.source=https://github.com/opendatahub-io/kube-auth-proxy \
      org.opencontainers.image.url=https://quay.io/opendatahub/kube-auth-proxy \
      org.opencontainers.image.title=kube-auth-proxy \
      org.opencontainers.image.version=${VERSION}

ENTRYPOINT ["/bin/entrypoint"]
