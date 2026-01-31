ARG GOLANG_ALPINE_TAG=1.25.6-alpine3.23
ARG ALPINE_VERSION=3.23

FROM golang:${GOLANG_ALPINE_TAG} AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates

WORKDIR /app

# Copy go module files
COPY go.mod ./
# go.sum may not exist for modules without external dependencies
RUN go mod download

# Copy source code
COPY cmd/ ./cmd/

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o grype-action ./cmd/grype_me

# Installer stage: fetch grype with signature verification (cosign present only here)
FROM alpine:${ALPINE_VERSION} AS grype-installer

RUN apk add --no-cache ca-certificates curl bash cosign

RUN curl -sSfL https://get.anchore.io/grype -o /tmp/install-grype.sh && \
    sh /tmp/install-grype.sh -v -b /tmp/grype && \
    rm /tmp/install-grype.sh && \
    /tmp/grype/grype version

# Download vulnerability database at build time for faster runtime
RUN /tmp/grype/grype db update

# Final stage - use same Alpine version as builder for consistency
FROM alpine:${ALPINE_VERSION}

# Install runtime dependencies (git needed for repo scans)
RUN apk add --no-cache ca-certificates bash git

# Copy verified grype binary from installer stage
COPY --from=grype-installer /tmp/grype/grype /usr/local/bin/grype

# Copy pre-downloaded vulnerability database
COPY --from=grype-installer /root/.cache/grype /root/.cache/grype

# Ensure Grype uses the baked-in DB regardless of HOME/XDG cache paths.
ENV GRYPE_DB_CACHE_DIR=/root/.cache/grype/db

# Copy the built application
COPY --from=builder /app/grype-action /usr/local/bin/grype-action

# Set working directory to GitHub Actions workspace mount point
# This ensures the action runs in the workspace directory where files are accessible
WORKDIR /github/workspace

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/grype-action"]
