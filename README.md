# Pomade Monorepo

Recovery protocol and implementation for nostr multisig signers.

> **📖 For protocol specification and implementation details, see [PROTOCOL.md](PROTOCOL.md)**

## ⚠️ Security Warning

**ALPHA SOFTWARE** - This project should be considered ALPHA and not ready for production use.

- Neither the protocol nor the code has been audited
- There could be fatal flaws resulting in key loss, theft, denial of service, or metadata leakage
- Use at your own risk

## Structure

This monorepo contains four packages:

- **[@pomade/core](packages/core)** - Core library with client, mailer, and signer classes, types, and interfaces
- **[@pomade/sqlite](packages/sqlite)** - SQLite storage adapter implementation
- **[@pomade/mailer](packages/mailer)** - Standalone mailer service for handling recovery challenges
- **[@pomade/signer](packages/signer)** - Standalone signer service for managing multisig sessions

## Getting Started

### Installation

```bash
pnpm install
```

### Building

Build all packages:

```bash
pnpm build
```

Build specific packages:

```bash
pnpm build:core
pnpm build:sqlite
pnpm build:mailer
pnpm build:signer
```

### Testing

```bash
pnpm test
```

### Development

Run the mailer service:

```bash
cd packages/mailer
cp .env.example .env
# Edit .env with your configuration
pnpm dev
```

Run the signer service:

```bash
cd packages/signer
cp .env.example .env
# Edit .env with your configuration
pnpm dev
```

## Package Details

### @pomade/core

The core library that can be integrated into any project. Provides:

- Client API for interacting with signers
- Mailer class for handling recovery method challenges
- Signer class for managing multisig sessions
- Storage interfaces (IStorage, IStorageFactory)
- Type definitions and schemas

**Installation:**

```bash
npm install @pomade/core
```

See [packages/core/README.md](packages/core/README.md) for detailed documentation.

### @pomade/sqlite

SQLite storage adapter for pomade. Provides a persistent storage implementation using better-sqlite3.

**Installation:**

```bash
npm install @pomade/sqlite
```

See [packages/sqlite/README.md](packages/sqlite/README.md) for usage examples.

### @pomade/mailer

Standalone mailer service that listens for recovery challenges and sends validation/recovery notifications. Supports console logging and webhook providers.

See [packages/mailer/README.md](packages/mailer/README.md) for configuration and deployment.

### @pomade/signer

Standalone signer service that manages multisig sessions, handles signing requests, and coordinates recovery flows.

See [packages/signer/README.md](packages/signer/README.md) for configuration and deployment.

## Docker

Both mailer and signer services include Dockerfiles for easy deployment:

```bash
# Build and run mailer
cd packages/mailer
docker build -t pomade-mailer .
docker run -v $(pwd)/data:/data --env-file .env pomade-mailer

# Build and run signer
cd packages/signer
docker build -t pomade-signer .
docker run -v $(pwd)/data:/data --env-file .env pomade-signer
```

## License

MIT
