# frost-taproot

Rust implementation of BIP-340 FROST (Flexible Round-Optimized Schnorr Threshold) signatures for Bitcoin Taproot.

## Features

- **FROST signing** - Threshold signatures compatible with BIP-340 Schnorr
- **Trusted dealer** - Centralized key generation and share distribution
- **DKG (Distributed Key Generation)** - Decentralized key generation without a trusted dealer
- **Share refresh** - Refresh shares without changing the group public key
- **Share recovery** - Recover shares using VSS (Verifiable Secret Sharing)
- **Compatible** - Compatible with the @cmdruid/frost TypeScript implementation

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
frost-taproot = { path = "../frost-taproot-rust" }
```

## Modules

- `ecc` - Elliptic curve cryptography primitives (secp256k1)
- `frost` - Core FROST implementation (dealer, DKG, signing, ECDH)
- `types` - Type definitions for shares, groups, commitments, and signatures
- `commit` - Commitment schemes for FROST nonces
- `context` - Signing context for BIP-340 compatible signatures
- `ecdh` - Elliptic Curve Diffie-Hellman key exchange
- `group` - Group management and validation
- `helpers` - Utility functions for FROST operations
- `poly` - Polynomial operations for secret sharing
- `recover` - Share recovery using VSS
- `refresh` - Share refresh protocols
- `shares` - Share generation and validation
- `sign` - BIP-340 compatible signing
- `vss` - Verifiable Secret Sharing

## Testing

```bash
cargo test
```

## License

MIT
