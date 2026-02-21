# Build stage
FROM rust:1.85-alpine AS builder

# Install build dependencies
RUN apk add --no-cache musl-dev

WORKDIR /app

# Copy frost-taproot first (dependency of pomade-signer)
COPY frost-taproot ./frost-taproot

# Copy pomade-signer
COPY pomade-signer ./pomade-signer

# Build in release mode
WORKDIR /app/pomade-signer
RUN cargo build --release

# Runtime stage
FROM alpine:latest

# Install runtime dependencies
RUN apk add --no-cache ca-certificates

WORKDIR /app

# Copy the built binary from builder
COPY --from=builder /app/pomade-signer/target/release/pomade-signer /usr/local/bin/pomade-signer

# Create data directory
RUN mkdir -p /data

# Set default environment variables
ENV DB_PATH=/data
ENV LISTEN_ADDR=0.0.0.0:3000
ENV REGISTER_POW=20
ENV MAIL_FROM_EMAIL=noreply@example.com
ENV MAIL_FROM_NAME="Pomade Signer"

EXPOSE 3000

CMD ["pomade-signer"]
