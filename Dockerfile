ARG GRYPE_CACHEBUST=0

FROM golang:1.26.2-bookworm@sha256:47ce5636e9936b2c5cbf708925578ef386b4f8872aec74a67bd13a627d242b19 AS builder

# Builder uses only Go toolchain and module downloads; no extra OS packages needed.

WORKDIR /app

# Copy go module files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY cmd/ ./cmd/

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o grype-action ./cmd/grypeme

# Prepare runtime directory skeleton for scratch image.
# Scratch has no shell or mkdir, so directories must be created in a build
# stage and COPYed into the final image with the desired ownership.
RUN mkdir -p /opt/runtime/app/.cache/grype /opt/runtime/app/tmp /opt/runtime/github/workspace && \
    touch /opt/runtime/app/.keep /opt/runtime/app/tmp/.keep /opt/runtime/github/workspace/.keep

# Installer stage: fetch grype with signature verification.
# Kept on Alpine intentionally:
# - `cosign` is straightforward to install via `apk`
# - this stage is not shipped in the final runtime image
# - runtime attack surface is still governed by the scratch final stage
#
# Using Bookworm here could reuse a Debian base layer, but cache reuse is mostly
# a build-time performance optimization and does not improve runtime security.
FROM alpine:3.23@sha256:5b10f432ef3da1b8d4c7eb6c487f2f5a8f096bc91145e68878dd4a5019afde11 AS grype-installer

ARG GRYPE_CACHEBUST

# ca-certificates: installs the latest Mozilla CA bundle from the Alpine
# package repo.  Since the image is rebuilt daily the trust store stays fresh.
RUN apk add --no-cache ca-certificates curl bash cosign

RUN echo "$GRYPE_CACHEBUST" >/dev/null && \
    curl -sSfL https://get.anchore.io/grype -o /tmp/install-grype.sh && \
    sh /tmp/install-grype.sh -v -b /tmp/grype && \
    rm /tmp/install-grype.sh && \
    /tmp/grype/grype version

# Download vulnerability database at build time for faster runtime
RUN echo "$GRYPE_CACHEBUST" >/dev/null && /tmp/grype/grype db update

# Final stage - scratch for minimal attack surface.
FROM scratch

# Runtime trust store for outbound HTTPS (grype DB/API and GitHub APIs).
COPY --from=grype-installer /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

# Create runtime paths with explicit ownership for the non-privileged user.
# /app is the application home (no actual OS user exists in scratch).
COPY --from=builder --chown=10001:10001 /opt/runtime/app /app
COPY --from=builder --chown=10001:10001 /opt/runtime/github/workspace /github/workspace

# Copy verified grype binary from installer stage
COPY --from=grype-installer /tmp/grype/grype /usr/local/bin/grype

# Copy pre-downloaded vulnerability database with proper ownership
COPY --from=grype-installer --chown=10001:10001 /root/.cache/grype /app/.cache/grype

# Ensure Grype uses the baked-in DB and TLS trust store in scratch runtime.
ENV HOME=/app
ENV GRYPE_DB_CACHE_DIR=/app/.cache/grype/db
ENV TMPDIR=/app/tmp
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

# Copy the built application
COPY --from=builder /app/grype-action /usr/local/bin/grype-action

# Set working directory to GitHub Actions workspace mount point
# This ensures the action runs in the workspace directory where files are accessible
WORKDIR /github/workspace

# Container starts as root only for startup permission fixups.
# The Go entrypoint immediately drops to UID/GID 10001 before scanning.

# Set the entrypoint (Go binary handles privilege drop internally)
ENTRYPOINT ["/usr/local/bin/grype-action"]
