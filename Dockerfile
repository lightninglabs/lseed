# --- Build stage ---
FROM golang:1.24-alpine AS builder

WORKDIR /build

# Copy source and Makefile.
COPY . .

# Install build tools.
RUN apk add --no-cache git make

# Build using Makefile (install places binary in /go/bin).
RUN make install

# --- Final stage ---
FROM gcr.io/distroless/static-debian11

# Add TLS certs for HTTPS/gRPC connections.
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy compiled binary.
COPY --from=builder /go/bin/lseed /lseed

# Run.
ENTRYPOINT ["/lseed"]
