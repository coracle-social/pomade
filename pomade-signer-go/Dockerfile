# Build stage
FROM golang:1.25 AS builder

WORKDIR /app

# Copy signer module files first for dependency resolution/cache
COPY pomade-signer-go/go.mod ./pomade-signer-go/go.mod
COPY pomade-signer-go/go.sum ./pomade-signer-go/go.sum

# Copy frost-taproot-go first (local replace target)
COPY frost-taproot-go ./frost-taproot-go

# Download dependencies
WORKDIR /app/pomade-signer-go
RUN go mod download

# Copy pomade-signer-go sources
WORKDIR /app
COPY pomade-signer-go ./pomade-signer-go

# Build static binary
WORKDIR /app/pomade-signer-go
RUN CGO_ENABLED=0 GOOS=linux go build -o /usr/local/bin/pomade-signer-go .

# Runtime stage
FROM gcr.io/distroless/static-debian12

WORKDIR /app

COPY --from=builder /usr/local/bin/pomade-signer-go /usr/local/bin/pomade-signer-go

RUN mkdir -p /data

ENV DB_PATH=/data/signer.db
ENV LISTEN_ADDR=0.0.0.0:3000
ENV REGISTER_POW=20
ENV MAIL_FROM_EMAIL=noreply@example.com
ENV MAIL_FROM_NAME="Pomade Signer"

EXPOSE 3000

CMD ["/usr/local/bin/pomade-signer-go"]
