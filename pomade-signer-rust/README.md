# pomade-signer

Rust HTTP signer server for the Pomade protocol.

For protocol specification, see [PROTOCOL.md](../PROTOCOL.md)

## Configuration

Required environment variables:
- `POMADE_URL` - The public URL for the signer
- `POMADE_SECRET` - Secret used to derive the key that encrypts all database values at rest

Optional environment variables:
- `POMADE_PORT` - Port for both bind address and signer URL base (default: `3000`)
- `POMADE_DATABASE` - Path to sled database directory (default: `./signer-db`)
- `MAIL_PROVIDER` - Email provider: `postmark`, `sendgrid`, `mailgun`, `sendlayer`, `resend`, or `smtp`
- `MAIL_FROM_EMAIL` - Sender email address (default: `noreply@example.com`)
- `MAIL_FROM_NAME` - Sender display name (default: `Pomade Signer`)
- `TEST_MODE` - Set to any value to disable mail-provider requirement, reduce argon memory settings, and set `REGISTER_POW` to `0`

Email provider specific variables:
- `POSTMARK_API_TOKEN` - For Postmark
- `SENDGRID_API_KEY` - For SendGrid
- `MAILGUN_API_KEY` and `MAILGUN_DOMAIN` - For Mailgun
- `MAILGUN_API_REGION` - `us` or `eu` (default: `us`)
- `SENDLAYER_API_KEY` - For SendLayer
- `RESEND_API_KEY` - For Resend
- `SMTP_HOST`, `SMTP_PORT` (default: `587`), `SMTP_USER`, `SMTP_PASSWORD` - For SMTP

## Running

### From source

```bash
cd pomade-signer-rust
POMADE_URL=http://127.0.0.1:3000 \
  POMADE_PORT=3000 \
  POMADE_SECRET=replace_with_long_random_secret \
  MAIL_PROVIDER=resend \
  MAIL_FROM_EMAIL=mailer@example.com \
  MAIL_FROM_NAME="Nostr Signer" \
  RESEND_API_KEY=your_key \
  cargo run --release
```

### With Docker (from repository)

```bash
mkdir -p data
docker build -f pomade-signer-rust/Dockerfile -t pomade-signer-rust .
docker run -v $(pwd)/data:/data \
  -e POMADE_URL=http://127.0.0.1:3000 \
  -e POMADE_PORT=3000 \
  -e POMADE_SECRET=replace_with_long_random_secret \
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
  -e POMADE_URL=http://127.0.0.1:3000 \
  -e POMADE_PORT=3000 \
  -e POMADE_SECRET=replace_with_long_random_secret \
  -e MAIL_PROVIDER=resend \
  -e MAIL_FROM_EMAIL=mailer@example.com \
  -e MAIL_FROM_NAME="Nostr Signer" \
  -e RESEND_API_KEY=your_key \
  -p 3000:3000 \
  ghcr.io/coracle-social/pomade-signer-rust:latest
```

## License

MIT
