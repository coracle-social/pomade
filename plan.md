Nostr uses secp256k1 keypairs which are used to sign, encrypt, and decrypt messages. This project has several goals:

- Secure key storage using Shamir Secret Sharing via FROST (Schnorr) threshold signatures.
- Non-interactive signing of messages.
- Email/otp "log in" such that users can recover a signing session with only an email.
- Key recovery such that users can recover their secret key, with no trusted third parties.

Todo:

- Switch away from nip 59, use ephemeral keys to hide metadata

## Components

### Client

A _client_ is an application that can be trusted to (temporarily) handle key material and request signatures on a user's behalf. A client identifies itself to signers by a freshly generated session-specific nostr public key.

### Signer

A _signer_ is a headless application that can be trusted to store key shards and collaborate in building threshold signatures. A signer is identified by a nostr public key. Communication is brokered by the signer's NIP 65 `inbox` and `outbox` relays.

### Recovery Service

A _recovery service_ is a headless application that can be trusted to send emails containing encrypted data to users, but not to access key material. Communication is brokered by the recovery service's NIP 65 `inbox` and `outbox` relays.

## Protocol Overview

### Registration

To create a new signing session, a client must first generate a new `client secret` which it will use to communicate with signers. This key MUST NOT be re-used, and MUST be distinct from the user's pubkey.

The client then shards the user's `secret key` and registers each shard with a different signer by creating a `kind REGISTER` rumor wrapped using [NIP 59](59.md), signed byt he client secret, and addressed to the signer's pubkey. A `shard` is a hex-encoded concatenation of:

- [encoded-public-shard]: given by:
  - [public-shard-id]: 2-bytes (little-endian)
  - [number-of-vss-commits]: 4-bytes (little-endian)
  - [shard-public-key]: 33-bytes (compressed)
  - <number-of-vss-commits> * [vss-commit]: 33-bytes (compressed) each
- [shard-secret-key]: 32-bytes (big-endian)
- [user-pubkey]: 33-bytes (compressed)

The threshold schema must also be defined using `signers_count` and `signers_threshold`.

The registration event MAY contain recovery information, including:

- `recovery_service` - the pubkey of a recovery service that implements this protocol.
- `recovery_email_hash` - the sha256 hash of the user's email.
- `recovery_email_ciphertext` - the user's email encrypted to `recovery_service` using nip 44.

This prevents the signer from learning the email of the user, while also enabling it to pass the email along to the recovery service.

```typescript
nip59_wrap("<signer pubkey>", {
  "kind": REGISTER,
  "pubkey": "<client pubkey>",
  "tags": [
    ["shard", "<hex encoded secret key shard>"],
    ["signers_count", "<total number of signers in key deal>"],
    ["signers_threshold", "<number of signers required for signing>"],
    ["recovery_service", "<recovery service pubkey>"],
    ["recovery_email_hash", "<sha256 of user email>"],
    ["recovery_email_ciphertext", "<user email nip44 encrypted to recovery_service>"],
  ],
})
```

The signer must then explicitly accept or (optionally) reject the shard. If the signer accepts the shard, it must include a `secret` which the client can later use to authorize collaborative signing.

```typescript
nip59_wrap("<client pubkey>", {
  "kind": REGISTER_ACK,
  "pubkey": "<signer pubkey>",
  "content": "<human readable message>",
  "tags": [
    ["secret", "<client secrete>"],
    ["status", "<error|pending|ok>"],
    ["e", "<kind REGISTER rumor id>"],
  ],
})
```

The same signer MUST NOT be used multiple times for different shards of the same key.

### Signing

When a client wants to sign an event, it should choose at least `signers_threshold` signers and send a `kind COMMIT_REQUEST` event with a `p` tag indicating the user's pubkey, signed using the `client secret`.

```typescript
nip59_wrap("<signer pubkey>", {
  "kind": COMMIT_REQUEST,
  "pubkey": "<client pubkey>",
  "tags": [
    ["p", "<user pubkey>"],
  ],
})
```

The signer must then look up the `kind REGISTER` event corresponding to the `signer pubkey` AND the `user pubkey` in order to generate its local commitments (a pair of public and private nonces). It must then send the public parts to the client in a `kind COMMIT` "commit event", as follows:

```typescript
nip59_wrap("<client pubkey>", {
  "kind": COMMIT,
  "pubkey": "<signer pubkey>",
  "tags": [
    ["commit", "<hex encoded commit>"],
    ["e", "<commit request event id>"],
    ["p", "<user pubkey>"]
  ],
})
```

In which the `commit` tag contains the hex-encoded concatenation of:

- [commit-id]: 8-bytes (little-endian)
- [signer-id]: 2-bytes (little-endian)
- [binding-nonce-point]: 33-bytes (compressed)
- [hiding-nonce-point]: 33-bytes (compressed)

Upon receiving commits from all signers, the client then aggregates the commits into a group commit and sends it back to all the signers using a `kind COMMIT_GROUP`, along with the event that is to be signed:

```typescript
nip59_wrap("<signer pubkey>", {
  "kind": COMMIT_GROUP,
  "pubkey": "<client pubkey>",
  "tags": [
    ["commit", "<hex encoded group commit>"],
    ["event", "<JSON-encoded event to be signed>"],
  ],
})
```

In which the `commit` tag contains the hex-encoded concatenation of:

- [first-nonce]: 33-bytes (compressed)
- [second-nonce]: 33-bytes (compressed)

Finally, each signer uses all commits together with their secret nonces and the hash of the event to be signed to produce a partial signature and sends that back to the client in a `kind PARTIAL_SIGNATURE` event:

```typescript
nip59_wrap("<client pubkey>", {
  "kind": PARTIAL_SIGNATURE,
  "pubkey": "<signer pubkey>",
  "tags": [
    ["e", "<COMMIT_GROUP event id>"],
    ["sig", "<hex encoded partial signature>"],
  ],
})
```

In which the `sig` tag contains the hex-encoded concatenation of:

- [signer-id]: 2-bytes (little-endian)
- [partial-signature-scalar]: 32-bytes (big-endian)

The client then combines the partial signatures into an aggregated signature which can be applied to the event.

### Recovery

To recover the user's original `secret key` by email alone, a client must request the user's email and get its `sha256` hash. Then, it must generate a new single-use `recovery key`. It then sends this to each signer using a `kind RECOVER_SHARD` rumor, wrapped using [NIP 59](59.md):

```typescript
nip59_wrap("<signer pubkey>", {
  "kind": RECOVER_SHARD,
  "pubkey": "<recovery pubkey>",
  "tags": [
    ["recovery_email_hash", "<sha256 hash of user email>"],
  ],
})
```

Each signer then finds the shard that was registered with `recovery_email_hash` and encrypts it to the `recovery_service` provided when the shard was registered. It then sends this shard along with the `recovery_email_ciphertext` to the `recovery_service` using a `kind RELEASE_SHARD` rumor, wrapped using [NIP 59](59.md):

```typescript
nip59_wrap("<recovery service pubkey>", {
  "kind": RELEASE_SHARD,
  "pubkey": "<signer pubkey>",
  "tags": [
    ["threshold", "<deal threshold>"],
    ["recovery_pubkey", "<recovery pubkey>"],
    ["recovery_email_ciphertext", "<nip44 encrypted user email>"],
    ["shard_ciphertext", "<encrypted hex encoded secret key shard>"],
  ],
})
```

The recovery service waits until `threshold` shards have been received and sends all `shard_ciphertext` values to the decrypted `recovery_email`.

The user can then copy the encrypted shards into their recovery client, which uses the `secret key` the user generated at the beginning of the process to decrypt all shards and reconstitute the secret key.

### Login

This is very similar to the recovery process, except that the _client_ never sees the user's secret key, and it requires all registered bunkers to respond in order to restore the signing session.

To log in to a user's existing signing session by email alone, a client must request the user's email and get its `sha256` hash. Then, it must generate a new single-use `login key`. It then sends this to each signer using a `kind REQUEST_OTP` rumor, wrapped using [NIP 59](59.md):

```typescript
nip59_wrap("<signer pubkey>", {
  "kind": REQUEST_OTP,
  "pubkey": "<login pubkey>",
  "tags": [
    ["recovery_email_hash", "<sha256 hash of user email>"],
  ],
})
```

Each signer then generates a single-use expiring OTP and associates it with the shard that was registered with `recovery_email_hash`. The signer then encrypts the OTP and sends it to the `recovery_service` using a `kind SEND_OTP` rumor, wrapped using [NIP 59](59.md):

```typescript
nip59_wrap("<recovery service pubkey>", {
  "kind": SEND_OTP,
  "pubkey": "<signer pubkey>",
  "tags": [
    ["signers_count", "<number of signers in the deal>"],
    ["signers_threshold", "<number of signers required for signing>"],
    ["login_pubkey", "<login pubkey>"],
    ["recovery_email_ciphertext", "<nip44 encrypted user email>"],
    ["otp_ciphertext", "<encrypted OTP>"],
  ],
})
```

The recovery service waits until at least `signers_threshold` (ideally, `signers_count`) shards have been received, concatenates the signer's pubkeys and OTP codes, and sends the payload to the decrypted `recovery_email`.

The user can then copy the encrypted shards into their recovery client, which uses the `secret key` the user generated at the beginning of the process to decrypt all shards and reconstitute the secret key.

The user can then copy the payload into their client, which decrypts all payloads and for each signer sends a `kind OTP_LOGIN` rumor, wrapped using [NIP 59](59.md):

```typescript
nip59_wrap("<signer pubkey>", {
  "kind": OTP_LOGIN,
  "pubkey": "<login pubkey>",
  "tags": [
    ["otp", "<otp code>"],
    ["recovery_email_hash", "<sha256 of user email>"],
  ],
})
```

The signer must then explicitly accept or (optionally) reject the OTP. If the signer accepts it, it must include a `token` which the client can later use to broker collaborative signing.

```typescript
nip59_wrap("<login pubkey>", {
  "kind": OTP_RESPONSE,
  "pubkey": "<signer pubkey>",
  "content": "<human readable message>",
  "tags": [
    ["token", "<access token>"],
    ["status", "<error|pending|ok>"],
    ["e", "<kind OTP_LOGIN rumor id>"],
  ],
})
```

## implementation details

the signature algorithm is implemented roughly as described in the https://eprint.iacr.org/2023/899.pdf, with big inspiration from the code at https://github.com/LLFourn/secp256kfun/tree/8e6fd712717692d475287f4a964be57c8584f54e/schnorr_fun/src/frost. relative to the paper (but following secp256kfun) this implementations has the following substantial changes:

  - for BIP-340 compatibility, the key dealing algorithm negates the secret key before sharding if its public key's `y` is odd;
  - for BIP-340 compatibility, when creating partial signatures, signers have to compute the group commitment, and if it's `y` is odd then all the public nonces and their own private nonce is negated;
  - for BIP-340 compatibility, then signing challenge is computed with `taggedhash("BIP0340/challenge", group-commitment-x || user-pubkey-x || event_id)`;
  - because it felt appropriate, other parts of the algorithm that would use hashes also use `taggedhash()` with different tags, the code will speak better than I can.
