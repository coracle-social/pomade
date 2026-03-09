# pomade-signer-go

Go HTTP signer server for the Pomade protocol.

This implementation follows `pomade-signer-rust` and uses `frost-taproot-go` for all threshold cryptographic operations.

## Configuration

Required environment variables:

- `POMADE_URL` - The public URL for the signer
- `POMADE_SECRET` - Secret used to encrypt persisted values at rest

Optional environment variables:

- `POMADE_PORT` - Port for both bind address and signer URL base (default: `3000`)
- `POMADE_DATABASE` - BoltDB file path (default: `./signer.db`)
- `MAIL_PROVIDER` - `postmark`, `sendgrid`, `mailgun`, `sendlayer`, `resend`, or `smtp`
- `MAIL_FROM_EMAIL` - Sender email (default: `noreply@example.com`)
- `MAIL_FROM_NAME` - Sender name (default: `Pomade Signer`)
- `TEST_MODE` - Set to any value to disable mail-provider requirement, reduce argon memory settings, and set `REGISTER_POW` to `0`

Provider specific variables:

- `POSTMARK_API_TOKEN`
- `SENDGRID_API_KEY`
- `MAILGUN_API_KEY`, `MAILGUN_DOMAIN`, `MAILGUN_API_REGION`
- `SENDLAYER_API_KEY`
- `RESEND_API_KEY`
- `SMTP_HOST`, `SMTP_PORT` (default: `587`), `SMTP_USER`, `SMTP_PASSWORD`

## Running

```bash
cd pomade-signer-go
POMADE_URL=http://127.0.0.1:3000 \
POMADE_PORT=3000 \
POMADE_SECRET=replace_with_long_random_secret \
MAIL_PROVIDER=resend \
MAIL_FROM_EMAIL=mailer@example.com \
MAIL_FROM_NAME="Nostr Signer" \
RESEND_API_KEY=your_key \
go run .
```

### With Docker (from repository root)

```bash
mkdir -p data
docker build -f pomade-signer-go/Dockerfile -t pomade-signer-go .
docker run -v $(pwd)/data:/data \
  -e POMADE_URL=http://127.0.0.1:3000 \
  -e POMADE_PORT=3000 \
  -e POMADE_SECRET=replace_with_long_random_secret \
  -e MAIL_PROVIDER=resend \
  -e MAIL_FROM_EMAIL=mailer@example.com \
  -e MAIL_FROM_NAME="Nostr Signer" \
  -e RESEND_API_KEY=your_key \
  -p 3000:3000 \
  pomade-signer-go
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
  ghcr.io/coracle-social/pomade-signer-go:latest
```

## License

MIT
