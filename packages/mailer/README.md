# @pomade/mailer

Standalone mailer service for pomade. This service listens for recovery method challenges and recovery challenges on nostr relays and sends validation/recovery emails.

## Installation

From the monorepo root:

```bash
pnpm install
pnpm --filter @pomade/mailer build
```

## Configuration

Copy `.env.example` to `.env` and configure:

```bash
cp .env.example .env
```

Required environment variables:
- `POMADE_SECRET`: The mailer's hex nostr private key
- `POMADE_RELAYS`: Comma-separated list of relay URLs

Optional environment variables:
- `POMADE_DB_PATH`: Path to SQLite database (default: `./pomade-mailer.db`)
- `POMADE_PROVIDER`: Provider type - `console` or `postmark` (default: `console`)

Postmark provider configuration (required if `POMADE_PROVIDER=postmark`):
- `POMADE_POSTMARK_SERVER_TOKEN`: Your Postmark server API token
- `POMADE_POSTMARK_FROM_EMAIL`: Verified sender email address

## Running

### Development

```bash
pnpm --filter @pomade/mailer dev
```

### Production

```bash
pnpm --filter @pomade/mailer start
```

### Docker

```bash
docker build -t pomade-mailer .
docker run -v $(pwd)/data:/data --env-file .env pomade-mailer
```

## Providers

### Console Provider

Logs validation and recovery challenges to console. Useful for development and testing.

```bash
POMADE_PROVIDER=console
```

### Postmark Provider

Sends validation and recovery emails using [Postmark](https://postmarkapp.com/), a transactional email service.

**Setup:**
1. Sign up for a Postmark account
2. Create a server and get your Server API Token
3. Add and verify a sender signature (your from email address)
4. Configure environment variables:

```bash
POMADE_PROVIDER=postmark
POMADE_POSTMARK_SERVER_TOKEN=your-server-token-here
POMADE_POSTMARK_FROM_EMAIL=noreply@yourdomain.com
```

**Email Templates:**

The provider sends both plain text and HTML emails:

- **Validation emails**: Include the challenge code and optional callback URL
- **Recovery emails**: Include the pubkey, challenge code, and optional callback URL
