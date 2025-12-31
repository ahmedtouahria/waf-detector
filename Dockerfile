# Build stage
FROM golang:1.23-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git make

# Set working directory
WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -X main.Version=${VERSION} -X main.Commit=${COMMIT} -X main.BuildDate=${BUILD_DATE}" \
    -o waf-detector .

# Final stage
FROM alpine:latest

# Install ca-certificates for HTTPS requests
RUN apk --no-cache add ca-certificates

# Create non-root user
RUN addgroup -g 1000 waf && \
    adduser -D -u 1000 -G waf waf

WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/waf-detector /app/

# Change ownership
RUN chown -R waf:waf /app

# Switch to non-root user
USER waf

# Set entrypoint
ENTRYPOINT ["/app/waf-detector"]

# Default command (can be overridden)
CMD ["--help"]
