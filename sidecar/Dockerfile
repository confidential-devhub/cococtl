# Build stage
FROM golang:1.24 AS builder

WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o coco-secure-access .

# Runtime stage
FROM alpine:latest

# Install ca-certificates for HTTPS and ps for SSH commands
RUN apk --no-cache add ca-certificates procps

WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/coco-secure-access .

# Expose ports
EXPOSE 8443

# Run the sidecar
ENTRYPOINT ["/app/coco-secure-access"]
