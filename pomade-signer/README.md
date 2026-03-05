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

## License

MIT
