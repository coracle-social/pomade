# frost-taproot-go

A Go implementation of FROST (Flexible Round-Optimized Schnorr Threshold signatures) for Bitcoin taproot/secp256k1.

## Features

- **Trusted Dealer Key Generation**: Generate threshold signatures with a trusted dealer
- **Distributed Key Generation (DKG)**: Run Pedersen DKG without a trusted dealer
- **BIP340 Schnorr Signatures**: Produce standard Bitcoin-compatible signatures
- **Tweaked Keys**: Support for key tweaking (BIP-32 style derivation)
- **Threshold ECDH**: Derive shared secrets with threshold participants
- **Share Recovery**: Recover lost shares using threshold recovery
- **Proactive Secret Sharing**: Refresh shares without changing the group key

## Installation

```bash
go get github.com/frost-taproot/frost-taproot-go
```

## Quick Start

```go
package main

import (
    "fmt"
    "github.com/frost-taproot/frost-taproot-go/frost"
    "github.com/frost-taproot/frost-taproot-go/frost_taproot"
)

func main() {
    // Generate a 2-of-3 group using trusted dealer
    pkg, err := frost.GenerateDealerPackage(2, 3, nil)
    if err != nil {
        panic(err)
    }

    fmt.Printf("Group public key: %x\n", pkg.Group.GroupPk)

    // Each signer generates a nonce pair
    nonce1 := frost.GenerateNoncePair(pkg.Shares[0].Seckey)
    nonce2 := frost.GenerateNoncePair(pkg.Shares[1].Seckey)

    // Create signing session
    members := []uint32{1, 2}
    messages := []frost.SignMessage{
        {Message: []byte("hello world"), Tweaks: nil},
    }
    memberNonces := []frost.MemberNonce{
        frost.ToMemberNonce(nonce1, 1),
        frost.ToMemberNonce(nonce2, 2),
    }

    session, err := frost.CreateSignSession(&pkg.Group, members, messages, memberNonces)
    if err != nil {
        panic(err)
    }

    // Derive secret nonces and create partial signatures
    secretNonce1 := frost.DeriveSecretNonce(pkg.Shares[0].Seckey, nonce1.Code)
    psigPkg1, err := frost.CreatePartialSigPackage(&session, &pkg.Shares[0], &secretNonce1)
    if err != nil {
        panic(err)
    }

    secretNonce2 := frost.DeriveSecretNonce(pkg.Shares[1].Seckey, nonce2.Code)
    psigPkg2, err := frost.CreatePartialSigPackage(&session, &pkg.Shares[1], &secretNonce2)
    if err != nil {
        panic(err)
    }

    // Combine signatures
    signatures, err := frost.CombineSignatures(&session, &pkg.Group, []frost.PartialSigPackage{psigPkg1, psigPkg2})
    if err != nil {
        panic(err)
    }

    fmt.Printf("Signature: %x\n", signatures[0].Sig)
}
```

## Package Structure

- `ecc/` - Elliptic curve operations (secp256k1)
- `types/` - Core data structures
- `util/` - Utility functions
- `poly/` - Polynomial evaluation and Lagrange interpolation
- `vss/` - Verifiable secret sharing
- `shares/` - Share creation and verification
- `group/` - Group creation (trusted dealer)
- `commit/` - Nonce commitments
- `context/` - Signing context
- `sign/` - Signing operations
- `ecdh/` - Threshold ECDH
- `recover/` - Share recovery
- `refresh/` - Proactive secret sharing
- `frost/` - High-level API

## Tests

Run the tests:

```bash
go test ./...
```

## License

MIT
