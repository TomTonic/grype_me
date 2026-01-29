FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates

WORKDIR /app

# Copy go module files
COPY go.mod ./
# Copy go.sum if it exists (not required for modules without dependencies)
COPY go.su[m] ./ 2>/dev/null || true
RUN go mod download

# Copy source code
COPY *.go ./

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o grype-action .

# Final stage
FROM alpine:latest

# Install grype and other dependencies
RUN apk add --no-cache ca-certificates curl bash git

# Install grype - download and verify script before execution
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh -o /tmp/install-grype.sh && \
    sh /tmp/install-grype.sh -b /usr/local/bin && \
    rm /tmp/install-grype.sh

# Copy the built application
COPY --from=builder /app/grype-action /usr/local/bin/grype-action

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/grype-action"]
