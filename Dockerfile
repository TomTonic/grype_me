FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates

WORKDIR /app

# Copy go module files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY *.go ./

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o grype-action .

# Final stage
FROM alpine:latest

# Install grype and other dependencies
RUN apk add --no-cache ca-certificates curl bash git

# Install grype
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Copy the built application
COPY --from=builder /app/grype-action /usr/local/bin/grype-action

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/grype-action"]
