# @pomade/signer

Standalone signer service for pomade. This service manages multisig sessions, handles signing requests, and coordinates recovery flows.

For protocol specification, see [PROTOCOL.md](../../PROTOCOL.md)

## Configuration

Required environment variables:
- `POMADE_SECRET`: A nostr private key used for encryption at rest
- `MAIL_PROVIDER`: Email provider (`postmark`, `sendgrid`, `mailgun`, `sendlayer`, or `resend`)
- `MAIL_FROM_EMAIL`: Sender email address

Optional environment variables:
- `POMADE_DATABASE`: Path to SQLite database (default: `./pomade-signer.db`)
- `MAIL_FROM_NAME`: Sender name (default: "Pomade Signer")

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
cd packages/signer
pnpm install
POMADE_SECRET=your_nsec MAIL_PROVIDER=resend MAIL_FROM_EMAIL=mailer@example.com RESEND_API_KEY=your_key pnpm start
```

### With Docker (from repository)

```bash
mkdir -p data
docker build -f packages/signer/Dockerfile -t pomade-signer-ts .
docker run -v $(pwd)/data:/data \
  -e POMADE_SECRET=your_nsec \
  -e POMADE_RELAYS=wss://relay.example.com \
  -e MAIL_PROVIDER=resend \
  -e MAIL_FROM_EMAIL=mailer@example.com \
  -e RESEND_API_KEY=your_key \
  -p 3000:3000 \
  pomade-signer-ts
```

### From ghcr

```bash
mkdir -p data
docker run -v $(pwd)/data:/data \
  -e POMADE_SECRET=your_nsec \
  -e POMADE_RELAYS=wss://relay.example.com \
  -e MAIL_PROVIDER=resend \
  -e MAIL_FROM_EMAIL=mailer@example.com \
  -e RESEND_API_KEY=your_key \
  -p 3000:3000 \
  ghcr.io/coracle-social/pomade-signer-ts:latest
```
