# Pomade

A recovery protocol and implementation for nostr multisig signers.

For protocol specification and implementation details, see [PROTOCOL.md](PROTOCOL.md)

## Security Warning

**ALPHA SOFTWARE** - This project should be considered ALPHA and not ready for production use.

- Neither the protocol nor the code has been audited
- There could be fatal flaws resulting in key loss, theft, denial of service, or metadata leakage
- Use at your own risk

## Structure

This monorepo contains four packages:

- **[@pomade/core](packages/core)** - Core library with client and signer classes, types, and interfaces
- **[@pomade/signer](packages/signer)** - Standalone signer service for managing multisig sessions

## Getting Started

### Clients

To add pomade support to your client, simply add it to your project:

```sh
pnpm install @pomade/core
```

Then, follow the guide [here](INTEGRATION.md).

### Signers

To run your own signer, simply run:

You can then add the signer's pubkey to your client to use it. Note that signers MUST be run by trusted, independent third parties. A list of reputable signers is included below and in the source code - we recommend you use this list unless you have good reasons not to.

-

Also note that when logging in, all signers need to be contacted, which involves some pretty computationally-intensive hashing operations. For that reason, you should avoid adding a large number of signers to your app; 7-10 should be enough.

## Package Details

### @pomade/core

The core library that can be integrated into any project. Provides:

- Protocol type definitions and schemas
- Client API for interacting with signers
- Signer class for managing multisig sessions

**Installation:**

```bash
npm install @pomade/core
```

See [packages/core/README.md](packages/core/README.md) for detailed documentation.

### @pomade/signer

Standalone signer service that manages multisig sessions, handles signing requests, and coordinates recovery flows.

See [packages/signer/README.md](packages/signer/README.md) for configuration and deployment.

## Docker

The signer service includes a Dockerfile for easy deployment. Build from the repository root:

```bash
# Build and run signer
docker build -f packages/signer/Dockerfile -t pomade-signer .
docker run -v $(pwd)/data:/data --env-file packages/signer/.env pomade-signer
```

## License

MIT
