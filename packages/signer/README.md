# @pomade/signer

Standalone signer service for pomade. This service manages multisig sessions, handles signing requests, and coordinates recovery flows.

## Installation

From the monorepo root:

```bash
pnpm install
pnpm --filter @pomade/signer build
```

## Configuration

Copy `.env.example` to `.env` and configure:

```bash
cp .env.example .env
```

Required environment variables:
- `POMADE_SECRET`: Your nostr private key (hex or nsec format)
- `POMADE_RELAYS`: Comma-separated list of relay URLs

Optional environment variables:
- `POMADE_DB_PATH`: Path to SQLite database (default: `./pomade-signer.db`)

## Running

### Development

```bash
pnpm --filter @pomade/signer dev
```

### Production

```bash
pnpm --filter @pomade/signer start
```

### Docker

```bash
docker build -t pomade-signer .
docker run -v $(pwd)/data:/data --env-file .env pomade-signer
```

## Features

- Session registration and management
- Multisig signing requests
- ECDH key exchange
- Recovery method setup and validation
- Account recovery flows
- Session listing and deletion
