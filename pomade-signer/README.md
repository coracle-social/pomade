# pomade-signer

Rust HTTP signer server for the Pomade protocol.

For protocol specification, see [PROTOCOL.md](../PROTOCOL.md)

## Configuration

Required environment variables:
- `SIGNER_URL` - Publicly reachable URL of this server (e.g., `https://signer.example.com`)

Optional environment variables:
- `LISTEN_ADDR` - Address to listen on (default: `0.0.0.0:3000`)
- `DB_PATH` - Path to sled database directory (default: `./signer-db`)
- `REGISTER_POW` - Minimum proof-of-work difficulty for registration (default: `20`)
- `MAIL_PROVIDER` - Email provider: `postmark`, `sendgrid`, `mailgun`, `sendlayer`, or `resend`
- `MAIL_FROM_EMAIL` - Sender email address (default: `noreply@example.com`)
- `MAIL_FROM_NAME` - Sender display name (default: `Pomade Signer`)

Email provider specific variables:
- `POSTMARK_API_TOKEN` - For Postmark
- `SENDGRID_API_KEY` - For SendGrid
- `MAILGUN_API_KEY` and `MAILGUN_DOMAIN` - For Mailgun
- `MAILGUN_API_REGION` - `us` or `eu` (default: `us`)
- `SENDLAYER_API_KEY` - For SendLayer
- `RESEND_API_KEY` - For Resend

## Running

### From source

```bash
cd pomade-signer
SIGNER_URL=https://signer.example.com \
  MAIL_PROVIDER=resend \
  MAIL_FROM_EMAIL=mailer@example.com \
  MAIL_FROM_NAME="Nostr Signer" \
  RESEND_API_KEY=your_key \
  cargo run --release
```

### With Docker (from repository)

```bash
mkdir -p data
docker build -f pomade-signer/Dockerfile -t pomade-signer-rust .
docker run -v $(pwd)/data:/data \
  -e SIGNER_URL=https://signer.example.com \
  -e MAIL_PROVIDER=resend \
  -e MAIL_FROM_EMAIL=mailer@example.com \
  -e MAIL_FROM_NAME="Nostr Signer" \
  -e RESEND_API_KEY=your_key \
  -p 3000:3000 \
  pomade-signer-rust
```

### From ghcr

```bash
mkdir -p data
docker run -v $(pwd)/data:/data \
  -e SIGNER_URL=https://signer.example.com \
  -e MAIL_PROVIDER=resend \
  -e MAIL_FROM_EMAIL=mailer@example.com \
  -e MAIL_FROM_NAME="Nostr Signer" \
  -e RESEND_API_KEY=your_key \
  -p 3000:3000 \
  ghcr.io/coracle-social/pomade-signer-rust:latest
```

## Running in AWS Nitro Enclaves

Nitro Enclave mode compiles with `--features nitro` and provides:
- **Encrypted storage** — the sled database is AES-256-GCM encrypted at rest using a key provisioned from AWS KMS
- **Remote attestation** — a `POST /attest` endpoint returns a signed NSM attestation document
- **Sealed secrets** — API keys are fetched from KMS at startup using attestation-bound decryption; the host operator never sees plaintext secrets
- **VSOCK networking** — the server listens on a VSOCK port; a companion proxy on the parent instance bridges traffic to/from the internet

### Prerequisites

- An EC2 instance with Nitro Enclaves enabled (`--enclave-options Enabled=true`)
- `nitro-cli` installed on the parent instance
- `jq` installed on the parent instance (for the build script)
- Python 3.8+ on the parent instance (for the proxy)
- An AWS KMS symmetric key with a key policy that restricts decryption to callers presenting a valid attestation document (see [KMS key policy](#kms-key-policy))

### 1. Build the Enclave Image File (EIF)

Run from the repository root on the parent EC2 instance:

```bash
./scripts/build-eif.sh
```

This builds `pomade-signer.eif` and prints the PCR measurements:

```
==> PCR Measurements (pin these in your KMS key policy):

  PCR0 (image):   <hex>
  PCR1 (kernel):  <hex>
  PCR2 (app):     <hex>

==> KMS condition block:
{
  "StringEquals": {
    "kms:RecipientAttestation:PCR0": "<hex>",
    "kms:RecipientAttestation:PCR1": "<hex>",
    "kms:RecipientAttestation:PCR2": "<hex>"
  }
}
```

Re-run this script after every code change and update your KMS key policy before deploying.

### 2. KMS key policy

Create a KMS symmetric key and add a statement to its policy that allows decryption only from a genuine enclave running this exact build:

```json
{
  "Sid": "AllowNitroEnclaveDecrypt",
  "Effect": "Allow",
  "Principal": { "AWS": "arn:aws:iam::<account>:role/<instance-role>" },
  "Action": "kms:Decrypt",
  "Resource": "*",
  "Condition": {
    "StringEqualsIgnoreCase": {
      "kms:RecipientAttestation:PCR0": "<PCR0 from build script>",
      "kms:RecipientAttestation:PCR1": "<PCR1 from build script>",
      "kms:RecipientAttestation:PCR2": "<PCR2 from build script>"
    }
  }
}
```

### 3. Encrypt your secrets

Encrypt the sealing key (32 random bytes) and any API keys with your KMS key:

```bash
# Generate and encrypt a 32-byte sealing key
SEALING_KEY_CIPHERTEXT=$(dd if=/dev/urandom bs=32 count=1 2>/dev/null | \
  aws kms encrypt \
    --key-id <key-arn> \
    --plaintext fileb:///dev/stdin \
    --query CiphertextBlob \
    --output text)

# Encrypt the mailer API key
RESEND_CIPHERTEXT=$(echo -n "your_resend_api_key" | \
  aws kms encrypt \
    --key-id <key-arn> \
    --plaintext fileb:///dev/stdin \
    --query CiphertextBlob \
    --output text)
```

### 4. Start the parent proxy

The proxy bridges VSOCK traffic between the enclave and the internet. Run it on the parent instance:

```bash
python3 nitro-proxy/main.py \
  --inbound-tcp-port 443 \
  --inbound-vsock-port 3000 \
  --outbound-vsock-port 3001
```

| Option | Default | Description |
|---|---|---|
| `--inbound-tcp-port` | `443` | TCP port on the parent that external clients connect to |
| `--inbound-vsock-port` | `3000` | VSOCK port the enclave's HTTP server listens on |
| `--outbound-vsock-port` | `3001` | VSOCK port the enclave uses for outbound HTTPS (KMS, mailers) |

### 5. Run the enclave

```bash
nitro-cli run-enclave \
  --eif-path pomade-signer.eif \
  --memory 512 \
  --cpu-count 2 \
  --enclave-cid 4 \
  -- \
  --signer-url https://signer.example.com \
  --vsock-port 3000 \
  --outbound-vsock-port 3001 \
  --kms-region us-east-1 \
  --kms-sealing-key-arn arn:aws:kms:us-east-1:<account>:key/<key-id> \
  --kms-sealing-key-ciphertext "$SEALING_KEY_CIPHERTEXT" \
  --kms-secret "RESEND_API_KEY=$RESEND_CIPHERTEXT" \
  --mail-provider resend \
  --mail-from-email mailer@example.com \
  --mail-from-name "Nostr Signer"
```

Additional `--kms-secret NAME=ciphertext` flags can be passed for any other secrets (e.g. `MAILGUN_API_KEY`, `POSTMARK_API_TOKEN`). Each value is decrypted via KMS at startup and injected into the process environment.

### Nitro-specific environment variables / CLI flags

| Flag | Env var | Default | Description |
|---|---|---|---|
| `--vsock-port` | `VSOCK_PORT` | — | VSOCK port for the HTTP server (replaces `--listen`) |
| `--outbound-vsock-port` | `OUTBOUND_VSOCK_PORT` | `3001` | VSOCK port for outbound HTTP CONNECT proxy |
| `--kms-region` | `KMS_REGION` | `us-east-1` | AWS region for KMS calls |
| `--kms-sealing-key-arn` | `KMS_SEALING_KEY_ARN` | — | KMS key ARN for the sealing key |
| `--kms-sealing-key-ciphertext` | `KMS_SEALING_KEY_CIPHERTEXT` | — | Base64 KMS ciphertext of the 32-byte sealing key |
| `--kms-secret` | `KMS_SECRETS` (comma-separated) | — | `NAME=ciphertext` pairs for additional secrets |

## API Endpoints

All endpoints except `/attest` accept POST requests with JSON bodies and require NIP-42 HTTP authentication.

- `POST /register` - Register a new session with group and share
- `POST /sign` - Create a partial signature
- `POST /ecdh` - Perform ECDH key exchange
- `POST /recovery/setup` - Set up recovery method (email/password)
- `POST /challenge` - Request OTP challenge for recovery/login
- `POST /recovery/start` - Start recovery flow
- `POST /recovery/select` - Select session to recover
- `POST /login/start` - Start login flow
- `POST /login/select` - Select session to login
- `POST /session/list` - List sessions by group public key
- `POST /session/delete` - Delete a session

### POST /attest *(Nitro Enclave mode only)*

Returns a signed attestation document from the Nitro Secure Module (NSM). Clients can use this to verify they are communicating with a genuine enclave running a known build of pomade-signer before sending sensitive key shares.

**Request body** (all fields optional):

```json
{
  "user_data": "<base64>",
  "nonce":     "<base64>",
  "public_key": "<base64>"
}
```

All fields are arbitrary bytes that the NSM will embed verbatim in the signed document. A common pattern is to send a random `nonce` to prevent replay attacks, or a `public_key` to bind an ephemeral key to the enclave's identity.

**Response:**

```json
{
  "ok": true,
  "document": "<base64>"
}
```

`document` is the raw CBOR-encoded, NSM-signed attestation document. Verify it against the [Nitro Enclaves root CA](https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip) and check that PCR0/PCR1/PCR2 match the values produced by `scripts/build-eif.sh` for your trusted build.

**Error responses:**

```json
{ "ok": false, "message": "..." }
```

Returns HTTP 400 for malformed base64 input, HTTP 500 if the NSM device is unavailable.

## License

MIT
