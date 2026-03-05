# pomade-signer-go

Go HTTP signer server for the Pomade protocol.

This implementation follows `pomade-signer-rust` and uses `frost-taproot-go` for all threshold cryptographic operations.

## Configuration

Required environment variables:

- `SIGNER_URL` - Publicly reachable URL for this signer
- `POMADE_SECRET` - Secret used to encrypt persisted values at rest

Optional environment variables:

- `LISTEN_ADDR` - Listen address (default: `0.0.0.0:3000`)
- `DB_PATH` - BoltDB file path (default: `./signer.db`)
- `REGISTER_POW` - PoW threshold for registration (default: `20`, or `0` in `TEST_MODE`)
- `TEST_MODE` - Set to any value to disable mail-provider requirement and reduce argon memory settings
- `MAIL_PROVIDER` - `postmark`, `sendgrid`, `mailgun`, `sendlayer`, or `resend`
- `MAIL_FROM_EMAIL` - Sender email (default: `noreply@example.com`)
- `MAIL_FROM_NAME` - Sender name (default: `Pomade Signer`)

Provider specific variables:

- `POSTMARK_API_TOKEN`
- `SENDGRID_API_KEY`
- `MAILGUN_API_KEY`, `MAILGUN_DOMAIN`, `MAILGUN_API_REGION`
- `SENDLAYER_API_KEY`
- `RESEND_API_KEY`

## Running

```bash
cd pomade-signer-go
SIGNER_URL=https://signer.example.com \
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
  -e SIGNER_URL=https://signer.example.com \
  -e POMADE_SECRET=replace_with_long_random_secret \
  -e MAIL_PROVIDER=resend \
  -e MAIL_FROM_EMAIL=mailer@example.com \
  -e MAIL_FROM_NAME="Nostr Signer" \
  -e RESEND_API_KEY=your_key \
  -p 3000:3000 \
  pomade-signer-go
```
