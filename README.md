# Pomade

A recovery protocol and implementation for nostr multisig signers.

For protocol specification and implementation details, see [PROTOCOL.md](PROTOCOL.md)

## Security Warning

**ALPHA SOFTWARE** - This project should be considered ALPHA and not ready for production use.

- Neither the protocol nor the code has been audited
- There could be fatal flaws resulting in key loss, theft, denial of service, or metadata leakage
- Use at your own risk

## Getting Started

### Clients

To add pomade support to your client, simply add it to your project:

```sh
pnpm install @pomade/core
```

Then, follow the guide [here](INTEGRATION.md).

### Signers

To run your own signer see [DEPLOY.md](DEPLOY.md) for detailed instructions, or visit the README for the package you're planning to run to cut to the chase:

- [pomade-signer-rust](pomade-signer-rust/README.md)
- [pomade-signer-go][pomade-signer-rust/README.md)
- [pomade-signer-ts][packages/signer/README.md)

You can then add the signer's url to your client to use it. Note that signers MUST be run by trusted, independent third parties. A list of reputable signers is included below and in the source code - we recommend you use this list unless you have good reasons not to.

- https://pomade.coracle.social

Also note that when logging in, all signers need to be contacted, which involves some pretty computationally-intensive hashing operations. For that reason, you should avoid adding a large number of signers to your app; 7-10 should be more than enough.

## Package Details

### @pomade/core

The core library that can be integrated into any project. Provides:

- Protocol type definitions and schemas
- Client API for interacting with signers
- Signer class that can be used for demos or for managing a local shard

See [the readme](packages/core/README.md) for detailed documentation.

### @pomade/templates

A tiny repository for generating HTML email templates using MJML.

### @pomade/signer

Standalone signer service that manages multisig sessions, handles signing requests, and coordinates recovery flows.

See [the readme](packages/signer/README.md) for configuration and deployment.

### frost-taproot-rust

Rust implementation of BIP-340 FROST signatures including trusted key dealer and DKG flows, compatible with the @cmdruid/frost typescript implementation.

See [the readme](frost-taproot-rust/README.md) for configuration and deployment.

### pomade-signer-rust

Rust signer server with sled storage.

See [the readme](pomade-signer-rust/README.md) for configuration and deployment.

### frost-taproot-go

Go implementation of BIP-340 FROST signatures including trusted key dealer and DKG flows, compatible with the @cmdruid/frost typescript implementation.

See [the readme](frost-taproot-go/README.md) for configuration and deployment.

### pomade-signer-go

Go signer server with bbolt storage.

See [the readme](pomade-signer-go/README.md) for configuration and deployment.

## License

MIT
