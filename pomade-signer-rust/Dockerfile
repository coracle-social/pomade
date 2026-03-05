# Build stage
FROM rust:alpine AS builder

# Install build dependencies
RUN apk add --no-cache musl-dev openssl-dev openssl-libs-static pkgconf

WORKDIR /app

# Copy frost-taproot first (dependency of pomade-signer)
COPY frost-taproot-rust ./frost-taproot-rust

# Copy pomade-signer-rust
COPY pomade-signer-rust ./pomade-signer-rust

# Build in release mode
WORKDIR /app/pomade-signer-rust
RUN cargo build --release

# Runtime stage
FROM alpine:latest

# Install runtime dependencies
RUN apk add --no-cache ca-certificates

WORKDIR /app

# Copy the built binary from builder
COPY --from=builder /app/pomade-signer-rust/target/release/pomade-signer /usr/local/bin/pomade-signer

# Create data directory
RUN mkdir -p /data

# Set default environment variables
ENV POMADE_DATABASE=/data
ENV POMADE_URL=http://localhost:3000
ENV MAIL_FROM_EMAIL=noreply@example.com
ENV MAIL_FROM_NAME="Pomade Signer"

EXPOSE 3000

CMD ["pomade-signer"]
