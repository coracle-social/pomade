# @pomade/signer

Standalone signer service for pomade. This service manages multisig sessions, handles signing requests, and coordinates recovery flows.

## Configuration

Required environment variables:
- `POMADE_SECRET`: Your nostr private key (hex or nsec format)
- `POMADE_RELAYS`: Comma-separated list of relay URLs
- `MAIL_PROVIDER`: Email provider (postmark, sendgrid, mailgun, sendlayer, or resend)
- `MAIL_FROM_EMAIL`: Sender email address

Optional environment variables:
- `POMADE_DB_PATH`: Path to SQLite database (default: `./pomade-signer.db`)
- `MAIL_FROM_NAME`: Sender name (default: "Pomade Signer")

For detailed email provider configuration, see [MAILERS.md](../../MAILERS.md).

## Running

From ghcr:

```sh
mkdir -p data
cp packages/signer/.env{.example,} # Edit the env file to fill in your details
docker run -v $(pwd)/data:/data --env-file packages/signer/.env ghcr.io/coracle-social/pomade-signer:latest
```

From the repository root:

```sh
mkdir -p data
cp packages/signer/.env{.example,} # Edit the env file to fill in your details
docker build -f packages/signer/Dockerfile -t pomade-signer .
docker run -v $(pwd)/data:/data --env-file packages/signer/.env pomade-signer
```
