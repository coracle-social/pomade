# Build stage
FROM golang:1.25 AS builder

# libsecp256k1 provides the constant-time EC scalar multiplications used for
# signing and ECDH; pkg-config is consumed by the cgo directive in ecc/secp_ct.go.
# The build MUST run with CGO_ENABLED=1 — a CGO_ENABLED=0 build omits the cgo
# file and fails to compile, which is intentional (it prevents shipping a binary
# that falls back to the variable-time, timing-leaky scalar multiplication).
RUN apt-get update \
    && apt-get install -y --no-install-recommends libsecp256k1-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pomade-signer-go/go.mod ./pomade-signer-go/go.mod
COPY pomade-signer-go/go.sum ./pomade-signer-go/go.sum
COPY frost-taproot-go ./frost-taproot-go

WORKDIR /app/pomade-signer-go
RUN go mod download

WORKDIR /app
COPY pomade-signer-go ./pomade-signer-go

WORKDIR /app/pomade-signer-go
RUN CGO_ENABLED=1 GOOS=linux go build -o /usr/local/bin/pomade-signer-go .

# Runtime stage — glibc-based (cgo binary is dynamically linked), unlike the
# previous static distroless image.
FROM gcr.io/distroless/base-debian12

WORKDIR /app

COPY --from=builder /usr/local/bin/pomade-signer-go /usr/local/bin/pomade-signer-go
# Ship the shared library the binary links against. The glob matches the Debian
# multiarch dir (e.g. x86_64-linux-gnu / aarch64-linux-gnu); /usr/lib is on the
# default loader search path so the flattened copy resolves at runtime.
COPY --from=builder /usr/lib/*/libsecp256k1.so* /usr/lib/

ENV POMADE_DATABASE=/data/signer.db
ENV POMADE_URL=http://localhost:3000
ENV MAIL_FROM_EMAIL=noreply@example.com
ENV MAIL_FROM_NAME="Pomade Signer"

EXPOSE 3000

VOLUME ["/data"]

CMD ["/usr/local/bin/pomade-signer-go"]
