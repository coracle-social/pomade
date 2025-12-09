# Pomade

Nostr uses secp256k1 keypairs which are used to sign, encrypt, and decrypt messages. This project has several goals:

- Secure key storage using Shamir Secret Sharing via FROST (Schnorr) threshold signatures.
- Non-interactive signing of messages.
- Email/otp "log in" such that users can recover a signing session with only an email.
- Key recovery such that users can recover their secret key, with no trusted third parties.

## Components

### Client

A _client_ is an application that can be trusted to (temporarily) handle key material and request signatures on a user's behalf. A client identifies itself to signers by a freshly generated session-specific nostr public key.

### Signer

A _signer_ is a headless application that can be trusted to store key shards and collaborate in building threshold signatures. A signer is identified by a nostr public key. Communication is brokered by the signer's NIP 65 `inbox` and `outbox` relays.

### Email Service

A _email service_ is a headless application that can be trusted to send emails containing encrypted data to users, but not to access key material. Communication is brokered by the email service's NIP 65 `inbox` and `outbox` relays.

## Protocol Overview

### Registration

To create a new signing session, a client must first generate a new `client secret` which it will use to communicate with signers. This key MUST NOT be re-used, and MUST be distinct from the user's pubkey.

The client then shards the user's `secret key` and registers each shard with a different signer by creating a `kind REGISTER` event:

```typescript
{
  "kind": REGISTER,
  "pubkey": "<client pubkey>",
  "content": nip44_encrypt([
    ["shard", "<hex encoded secret key shard>"],
    ["pubkey", "<hex encoded user public key>"],
    ["signers_count", "<total number of signers in key deal>"],
    ["signers_threshold", "<number of signers required for signing>"],
    ["email_service", "<email service pubkey>"],
    ["email_hash", "<sha256 of user email>"],
    ["email_ciphertext", "<user email nip44 encrypted to email_service>"],
    ["email_collision_policy", "<replace|reject>"],
  ]),
  "tags": [
    ["p", "<signer pubkey>"]
  ],
}
```

The following public tags are required:

- `p` indicates the pubkey of the signer

The following private tags are required:

- `shard` is a shard of the user's private key (see below)
- `pubkey` is the user's hex-encoded public key
- `signers_count` is the total number of signers in the key deal
- `signers_threshold` is the number of signers required to sign an event

`shard` is a hex-encoded concatenation of:

- encoded-public-shard: given by:
  - public-shard-id: 2-bytes (little-endian)
  - number-of-vss-commits: 4-bytes (little-endian)
  - shard-public-key: 33-bytes (compressed)
  - <number-of-vss-commits> * vss-commit: 33-bytes (compressed) each
- shard-secret-key: 32-bytes (big-endian)
- user-pubkey: 33-bytes (compressed)

The registration event MAY contain recovery information in its private tags, including:

- `email_service` - the pubkey of a email service that implements this protocol.
- `email_hash` - the sha256 hash of the user's email.
- `email_ciphertext` - the user's email encrypted to `email_service` using nip 44.
- `email_collision_policy` - how signers should handle multiple pubkeys being associated with a single email.

This prevents the signer from learning the email of the user, while also enabling it to pass the email along to the email service.

Each signer must then explicitly accept or (optionally) reject the shard:

```typescript
{
  "kind": REGISTER_ACK,
  "pubkey": "<signer pubkey>",
  "content": nip44_encrypt([
    ["status", "<error|pending|ok>"],
    ["message", "<human readable message>"],
  ]),
  "tags": [
    ["p", "<client pubkey>"],
    ["e", "<kind REGISTER event id>"],
  ],
}
```

This event MUST include `status` and `message` in its private tags. If a `email` is included, signers MUST validate ownership of the email if provided (see below), in the meantime returning `pending` with a helpful `message`. When the email has been validated, the signer must then send another ack for the same event with `status=ok`.

Signers MUST reject registration events that associate a second pubkey with an email already registered, since there's no way for users to easily select a pubkey when recovering via email. Clients SHOULD set `email_collision_policy` to `reject` the first time a user attempts to register. If registration fails, signers MUST return an error in the ack event. The client SHOULD show this error to a user and MAY re-try with `replace` as the collision policy. Signers MUST NOT replace sessions until the user's email has been validated.

The same signer MUST NOT be used multiple times for different shards of the same key.

### Email Validation

In order to validate a user's email, a signer must send a `kind VALIDATE_EMAIL` event to the given `email service`:

```typescript
{
  "kind": VALIDATE_EMAIL,
  "pubkey": "<signer pubkey>",
  "content": nip44_encrypt([
    ["id", "<sha256(user pubkey, client pubkey)>"],
    ["email_ciphertext", "<nip44 encrypted user email>"],
  ]),
  "tags": [
    ["p", "<email service pubkey>"],
  ],
}
```

This event must include a request `id` of `sha256(user pubkey, client pubkey)` to allow email services to accurately batch requests in order to avoid duplicate emails being sent to the user without false positives (which can lead to a denial of service if `email_collision_policy` is set to `replace`).

When the user has completed the verification process, the email service must send a `kind VALIDATE_EMAIL_ACK` to each signer:

```typescript
{
  "kind": VALIDATE_EMAIL_ACK,
  "pubkey": "<email service pubkey>",
  "content": nip44_encrypt([
    ["id", "<sha256(user pubkey, client pubkey)>"],
  ]),
  "tags": [
    ["p", "<signer pubkey>"],
  ],
}
```

### Signing

When a client wants to sign an event, it must choose at least `signers_threshold` signers and send a `kind COMMIT_REQUEST` event with a private `pubkey` tag indicating the user's pubkey to each signer.

```typescript
{
  "kind": COMMIT_REQUEST,
  "pubkey": "<client pubkey>",
  "content": nip44_encrypt([
    ["pubkey", "<user pubkey>"],
  ]),
  "tags": [
    ["p", "<signer pubkey>"],
  ],
}
```

The signer must then look up the `kind REGISTER` event corresponding to the given `client pubkey` AND the `user pubkey` in order to generate its local commitments (a pair of public and private nonces). It must then send the public nonces to the client in a `kind COMMIT` event:

```typescript
{
  "kind": COMMIT,
  "pubkey": "<signer pubkey>",
  "content": nip44_encrypt([
    ["commit", "<hex encoded commit>"],
  ]),
  "tags": [
    ["p", "<client pubkey>"],
    ["e", "<kind COMMIT_REQUEST event id>"],
  ],
}
```

In which the `commit` tag contains the hex-encoded concatenation of:

- commit-id: 8-bytes (little-endian)
- signer-id: 2-bytes (little-endian)
- binding-nonce-point: 33-bytes (compressed)
- hiding-nonce-point: 33-bytes (compressed)

Upon receiving commits from all signers, the client then aggregates the commits into a group commit and sends it back to all the signers using a `kind COMMIT_GROUP`, along with the event that is to be signed:

```typescript
{
  "kind": COMMIT_GROUP,
  "pubkey": "<client pubkey>",
  "content": nip44_encrypt([
    ["commit", "<hex encoded group commit>"],
    ["event", "<JSON-encoded event to be signed>"],
  ]),
  "tags": [
    ["p", "<signer pubkey>"],
  ],
}
```

In which the `commit` tag contains the hex-encoded concatenation of:

- first-nonce: 33-bytes (compressed)
- second-nonce: 33-bytes (compressed)

Finally, each signer uses all commits together with their secret nonces and the hash of the event to be signed to produce a partial signature and sends that back to the client in a `kind PARTIAL_SIGNATURE` event:

```typescript
{
  "kind": PARTIAL_SIGNATURE,
  "pubkey": "<signer pubkey>",
  "content": nip44_encrypt([
    ["sig", "<hex encoded partial signature>"],
  ]),
  "tags": [
    ["p", "<client pubkey>"],
    ["e", "<kind COMMIT_GROUP event id>"],
  ],
}
```

In which the `sig` tag contains the hex-encoded concatenation of:

- signer-id: 2-bytes (little-endian)
- partial-signature-scalar: 32-bytes (big-endian)

The client then combines the partial signatures into an aggregated signature which can be applied to the event.

### Session deletion

When a user wishes to log out of any active signing sessions, their client can send a `kind UNREGISTER` event to all signers:

```typescript
{
  "kind": UNREGISTER,
  "pubkey": "<client pubkey>",
  "content": nip44_encrypt([
    ["revoke", "<current|others|all>"],
  ]),
  "tags": [
    ["p", "<signer pubkey>"],
  ],
}
```

The client MUST include a private `revoke` tag which indicates whether the user wants to sign out of the current session only, other sessions, or all sessions connected to the user's `pubkey`. Signers MUST delete all key material from their database. Clients SHOULD inform users that this action makes key recovery impossible.

### Recovery

To recover the user's original `secret key` by email alone without access to an active `client key`, a client must `sha256` hash the user's email and generate a new single-use `recovery key`. It then sends this to each signer using a `kind RECOVER_SHARD` event:

```typescript
{
  "kind": RECOVER_SHARD,
  "pubkey": "<recovery pubkey>",
  "content": nip44_encrypt([
    ["email_hash", "<sha256 hash of user email>"],
  ]),
  "tags": [
    ["p", "<signer pubkey>"],
  ],
}
```

Each signer then finds any shards that were registered with `email_hash` and encrypts them to the `email_service` provided when the shard was registered. It then sends these shards, along with their corresponding `email_ciphertext` to the `email_service` using a `kind RELEASE_SHARD` event:

```typescript
{
  "kind": RECOVER_SHARD,
  "pubkey": "<signer pubkey>",
  "content": nip44_encrypt([
    ["signers_count", "<number of signers in the deal>"],
    ["signers_threshold", "<number of signers required for signing>"],
    ["recovery_pubkey", "<recovery pubkey>"],
    ["email_ciphertext", "<nip44 encrypted user email>"],
    ["shard_ciphertext", "<encrypted hex encoded secret key shard>"],
  ]),
  "tags": [
    ["p", "<email service pubkey>"],
  ],
}
```

The email service waits until at least `signers_threshold` shards have been received and sends all `shard_ciphertext` values to the decrypted `email`.

The user can then copy the encrypted shards into their recovery client, which uses the `recovery key` the user generated at the beginning of the process to decrypt all shards and reconstitute the user's secret key.

### Login

This is very similar to the recovery process, except that the client never sees the user's secret key, and it requires _all_ registered bunkers to respond in order to restore the signing session.

To log in to a user's existing signing session by email alone, a client must request the user's email and get its `sha256` hash. Then, it must generate a new single-use `login key`. It then sends this to each signer using a `kind REQUEST_OTP` event:

```typescript
{
  "kind": REQUEST_OTP,
  "pubkey": "<login pubkey>",
  "content": nip44_encrypt([
    ["email_hash", "<sha256 hash of user email>"],
  ]),
  "tags": [
    ["p", "<signer pubkey>"],
  ],
}
```

Each signer then generates a single-use expiring OTP and associates it with the shard that was registered with `email_hash`. The signer then encrypts the OTP and sends it to the `email_service` using a `kind SEND_OTP` event:

```typescript
{
  "kind": SEND_OTP,
  "pubkey": "<signer pubkey>",
  "content": nip44_encrypt([
    ["signers_count", "<number of signers in the deal>"],
    ["signers_threshold", "<number of signers required for signing>"],
    ["login_pubkey", "<login pubkey>"],
    ["email_ciphertext", "<nip44 encrypted user email>"],
    ["otp_ciphertext", "<encrypted OTP>"],
  ]),
  "tags": [
    ["p", "<email service pubkey>"],
  ],
}
```

The email service waits until at least `signers_threshold` (ideally, `signers_count`) shards have been received and sends the payload to the decrypted `email`. The payload should be a base58 concatenation of the signers pubkeys and OTP codes in the following format:

`pubkey1:otp1_ciphertext,pubkey2,otp2_ciphertext`

The user can then copy the payload into their client, which generates a fresh `client secret`, decrypts all OPTs, and sends a `kind OTP_LOGIN` event to each signer:

```typescript
{
  "kind": OTP_LOGIN,
  "pubkey": "<client pubkey>",
  "content": nip44_encrypt([
    ["otp", "<otp code>"],
    ["email_hash", "<sha256 of user email>"],
  ]),
  "tags": [
    ["p", "<signer pubkey>"],
  ],
}
```

The signer must then explicitly accept or (optionally) reject the OTP using a `OTP_ACK` event. If the signer accepts it, it must create a new session with the given `client pubkey`.

```typescript
{
  "kind": OTP_ACK,
  "pubkey": "<signer pubkey>",
  "content": nip44_encrypt([
    ["status", "<error|pending|ok>"],
    ["message", "<error|pending|ok>"],
  ]),
  "tags": [
    ["p", "<client pubkey>"],
    ["e", "<kind OTP_LOGIN event id>"],
  ],
}
```

## Implementation Details

the signature algorithm is implemented roughly as described in the https://eprint.iacr.org/2023/899.pdf, with big inspiration from the code at https://github.com/LLFourn/secp256kfun/tree/8e6fd712717692d475287f4a964be57c8584f54e/schnorr_fun/src/frost. relative to the paper (but following secp256kfun) this implementations has the following substantial changes:

  - for BIP-340 compatibility, the key dealing algorithm negates the secret key before sharding if its public key's `y` is odd;
  - for BIP-340 compatibility, when creating partial signatures, signers have to compute the group commitment, and if it's `y` is odd then all the public nonces and their own private nonce is negated;
  - for BIP-340 compatibility, then signing challenge is computed with `taggedhash("BIP0340/challenge", group-commitment-x || user-pubkey-x || event_id)`;
  - because it felt appropriate, other parts of the algorithm that would use hashes also use `taggedhash()` with different tags, the code will speak better than I can.
