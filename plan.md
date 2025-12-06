Nostr uses secp256k1 keypairs which are used to sign, encrypt, and decrypt messages. This project has several goals:

- Secure key storage using Shamir Secret Sharing via FROST (Schnorr) threshold signatures.
- Non-interactive signing, encryption, and decryption of messages.
- Email/otp "log in" such that users can recover a signing session with only an email
- Key recovery such that users can recover their secret key, with no trusted third parties

# Components

## Signer

A _signer_ is a headless application that can be trusted to store key shards and collaborate in building threshold signatures. A signer is identified by a nostr public key. Communication is brokered by the signer's NIP 65 `inbox` and `outbox` relays.

## Recovery Service

A _recovery service_ is a headless application that can be trusted to send emails containing encrypted data to users, but not to access key material. Communication is brokered by the recovery service's NIP 65 `inbox` and `outbox` relays.

# Protocol Overview

## Registration

To create a new signing session, the _client_ shards the user's `secret key` and registers each shard with a different _signer_ by creating a `kind REGISTER` rumor wrapped using [NIP 59](59.md) and addressed to the signer's pubkey.

The registration event MAY contain recovery information, including:

- `recovery_service` - the pubkey of a recovery service that implements this protocol.
- `recovery_email_hash` - the sha256 hash of the user's email.
- `recovery_email_ciphertext` - the user's email encrypted to `recovery_service` using nip 44.

This prevents the signer from learning the email of the user, while also enabling it to pass the email along to the recovery service.

```typescript
nip59_wrap("<signer pubkey>", {
  "kind": REGISTER,
  "pubkey": "<user pubkey>",
  "tags": [
    ["shard", "<hex encoded secret key shard>"],
    ["recovery_service", "<recovery service pubkey>"],
    ["recovery_email_hash", "<sha256 of user email>"],
    ["recovery_email_ciphertext", "<user email nip44 encrypted to recovery_service>"],
  ],
})
```

The signer must then explicitly accept or (optionally) reject the shard. If the signer accepts the shard, it must include a `token` which the client can later use to broker collaborative signing.

```typescript
nip59_wrap("<user pubkey>", {
  "kind": REGISTER_ACK,
  "pubkey": "<signer pubkey>",
  "content": "<human readable message>",
  "tags": [
    ["token", "<access token>"],
    ["status", "<error|pending|ok>"],
    ["e", "<kind REGISTER rumor id>"],
  ],
})
```

## Signing

[TODO]: detail collaborative signing stuff, with the client as the coordinator

## Recovery

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

## Login

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

concatenates it with the signer's pubkey, encrypts the bundle to `recovery_service`, then sends `{encrypted_payload, encrypted_recovery_email}` to `recovery_service`.

```typescript
nip59_wrap("<recovery service pubkey>", {
  "kind": SEND_OTP,
  "pubkey": "<signer pubkey>",
  "tags": [
    ["signers_count", "<number of signers in the deal>"],
    ["login_pubkey", "<login pubkey>"],
    ["recovery_email_ciphertext", "<nip44 encrypted user email>"],
    ["otp_ciphertext", "<encrypted OTP>"],
  ],
})
```

The recovery service waits until `signers_count` shards have been received, concatenates the signer's pubkeys and OTP codes, and sends the payload to the decrypted `recovery_email`.

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
