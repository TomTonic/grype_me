ARG GRYPE_CACHEBUST=0

FROM golang:1.26.1-alpine3.23@sha256:2389ebfa5b7f43eeafbd6be0c3700cc46690ef842ad962f6c5bd6be49ed82039 AS builder

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
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o grype-action ./cmd/grypeme

# Installer stage: fetch grype with signature verification (cosign present only here)
FROM alpine:3.23@sha256:25109184c71bdad752c8312a8623239686a9a2071e8825f20acb8f2198c3f659 AS grype-installer

ARG GRYPE_CACHEBUST

RUN apk add --no-cache ca-certificates curl bash cosign

RUN echo "$GRYPE_CACHEBUST" >/dev/null && \
    curl -sSfL https://get.anchore.io/grype -o /tmp/install-grype.sh && \
    sh /tmp/install-grype.sh -v -b /tmp/grype && \
    rm /tmp/install-grype.sh && \
    /tmp/grype/grype version

# Download vulnerability database at build time for faster runtime
RUN echo "$GRYPE_CACHEBUST" >/dev/null && /tmp/grype/grype db update

# Final stage - copy grype, the database, and the built application into a minimal image
FROM alpine:3.23@sha256:25109184c71bdad752c8312a8623239686a9a2071e8825f20acb8f2198c3f659

# Install runtime dependencies (git needed for repo scans)
RUN apk add --no-cache ca-certificates git && apk upgrade --no-cache

# Create unprivileged runtime user and writable runtime directories.
RUN addgroup -S grype && adduser -S -G grype -u 10001 grype && \
    mkdir -p /home/grype/.cache/grype /tmp /github/workspace && \
    chown -R grype:grype /home/grype /tmp /github/workspace

# Copy verified grype binary from installer stage
COPY --from=grype-installer /tmp/grype/grype /usr/local/bin/grype

# Copy pre-downloaded vulnerability database
COPY --from=grype-installer /root/.cache/grype /home/grype/.cache/grype
RUN chown -R grype:grype /home/grype/.cache/grype

# Ensure Grype uses the baked-in DB regardless of HOME/XDG cache paths.
ENV HOME=/home/grype
ENV GRYPE_DB_CACHE_DIR=/home/grype/.cache/grype/db

# Copy the built application
COPY --from=builder /app/grype-action /usr/local/bin/grype-action

# Set working directory to GitHub Actions workspace mount point
# This ensures the action runs in the workspace directory where files are accessible
WORKDIR /github/workspace

# Drop root privileges for runtime.
USER grype

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/grype-action"]
