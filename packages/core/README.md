# @pomade/core

Core library for the Pomade protocol - recovery protocol and implementation for nostr multisig signers.

For protocol specification, see [PROTOCOL.md](../../PROTOCOL.md)

## Installation

```bash
npm install @pomade/core
```

## What's Included

- **Client** - Application-side interface for registering sessions, signing, and recovery
- **Signer** - Service for managing multisig sessions and creating partial signatures
- **Storage interfaces** - `IStorage` and `IStorageFactory` with in-memory implementation
- **Type definitions** - Complete TypeScript types and Zod schemas for all protocol messages

## Usage

```typescript
import {Client, Signer, inMemoryStorageFactory} from "@pomade/core"

// Register a new client session
const client = await Client.register(
  2, // threshold
  3, // n (number of signers)
  userSecret, // user's secret key
  true, // recovery enabled
)

// For running a signer service
const signer = new Signer({
  secret: signerSecretKey,
  relays: ["wss://relay.example.com"],
  storage: storageFactory,
})
```

For persistent storage, use [@pomade/sqlite](../sqlite) or implement your own `IStorageFactory`.

For ready-to-run services, see [@pomade/signer](../signer).

## License

MIT
