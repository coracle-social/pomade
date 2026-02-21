# pomade-signer

Rust HTTP signer server for the Pomade protocol.

## Features

- **HTTP API** - Built with axum for high performance
- **Sled storage** - Embedded database for session persistence
- **Email recovery** - OTP-based recovery via email (Postmark, SendGrid, Mailgun, SendLayer, Resend)
- **Password recovery** - Argon2id hashed password authentication
- **Proof-of-work** - NIP-13 proof-of-work required for registration
- **Rate limiting** - Per-client and per-email rate limiting
- **Nostr auth** - NIP-42 HTTP authentication

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

```bash
SIGNER_URL=https://signer.example.com \
  MAIL_PROVIDER=resend \
  MAIL_FROM_EMAIL=mailer@example.com \
  MAIL_FROM_NAME="Nostr Signer" \
  RESEND_API_KEY=your_key \
  cargo run --release
```

## API Endpoints

All endpoints accept POST requests with JSON bodies and require NIP-42 HTTP authentication.

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
