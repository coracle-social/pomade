# Build stage
FROM golang:1.25 AS builder

WORKDIR /app

COPY pomade-signer-go/go.mod ./pomade-signer-go/go.mod
COPY pomade-signer-go/go.sum ./pomade-signer-go/go.sum
COPY frost-taproot-go ./frost-taproot-go

WORKDIR /app/pomade-signer-go
RUN go mod download

WORKDIR /app
COPY pomade-signer-go ./pomade-signer-go

WORKDIR /app/pomade-signer-go
RUN CGO_ENABLED=0 GOOS=linux go build -o /usr/local/bin/pomade-signer-go .

# Runtime stage
FROM gcr.io/distroless/static-debian12

WORKDIR /app

COPY --from=builder /usr/local/bin/pomade-signer-go /usr/local/bin/pomade-signer-go

ENV DB_PATH=/data/signer.db
ENV LISTEN_ADDR=0.0.0.0:3000
ENV REGISTER_POW=20
ENV MAIL_FROM_EMAIL=noreply@example.com
ENV MAIL_FROM_NAME="Pomade Signer"

EXPOSE 3000

VOLUME ["/data"]

CMD ["/usr/local/bin/pomade-signer-go"]
