# Pomade

Nostr uses secp256k1 keypairs which are used to sign, encrypt, and decrypt messages. This project has several goals:

- Secure key storage using Shamir Secret Sharing via FROST (Schnorr) threshold signatures.
- Non-interactive signing of messages.
- Email/otp "log in" such that users can recover a signing session with only an email.
- Key recovery such that users can recover their secret key, with no trusted third parties.

WARNING: this protocol has not been audited, and I don't really know what I'm doing. There could be fatal flaws resulting in key loss, theft, denial of service, or metadata leakage. Use this at your own risk.

## Components

### Client

A _client_ is an application that can be trusted to (temporarily) handle key material and request signatures on a user's behalf. A client identifies itself to signers by a freshly generated session-specific nostr public key.

### Signer

A _signer_ is a headless application that can be trusted to store key shares and collaborate in building threshold signatures. A signer is identified by a nostr public key. Communication is brokered following NIP 65.

### Email Service

A _email service_ is a headless application that can be trusted to send emails containing encrypted data to users, but not to access key material. Communication is brokered following NIP 65.

## Protocol Overview

In order to protect message metadata, this protocol uses a single event kind, `28350`, for all requests. All events contain a private `method` tag that determines the semantics of the remaining tags.

### Registration

To create a new signing session, a client must first generate a new `client secret` which it will use to communicate with signers. This key MUST NOT be re-used, and MUST be distinct from the user's pubkey.

The client then shares the user's `secret key` and registers each share with a different signer by creating a `register/request` event:

```typescript
{
  "kind": 28350,
  "pubkey": "<client pubkey>",
  "content": nip44_encrypt([
    ["method", "register/request"],
    ["share", "<hex encoded share package>"],
    ["group", "<hex encoded group package>"],
    ["threshold", "<number of signers required for signing>"],
    ["email_service", "<email service pubkey>"],
    ["email_hash", "<sha256 of user email>"],
    ["email_ciphertext", "<user email nip44 encrypted to email_service>"],
  ]),
  "tags": [
    ["p", "<signer pubkey>"]
  ],
}
```

The following public tags are required:

- `p` indicates the pubkey of the signer

The following private tags are required:

- `share` is a `share package` containing the signer's secret share and nonces (see below)
- `group` is a `group package` containing the shared group configuration (see below)
- `threshold` is the number of signers required to sign an event

`share` is a hex-encoded concatenation of:

- `idx`: 4-bytes (little-endian) // Signer index
- `seckey`: 32-bytes (big-endian) // Secret key share
- `binder_sn`: 32-bytes (big-endian) // Binder secret nonce
- `hidden_sn`: 32-bytes (big-endian) // Hidden secret nonce

`group` is a hex-encoded concatenation of:

- `group_pk`: 33-bytes (compressed) // The user's public key
- `threshold`: 4-bytes (little-endian) // Signers required
- For each member:
  - `idx`: 4-bytes (little-endian)
  - `pubkey`: 33-bytes (compressed) // Member's public key
  - `binder_pn`: 33-bytes (compressed) // Binder public nonce
  - `hidden_pn`: 33-bytes (compressed) // Hidden public nonce

The registration event MAY contain recovery information in its private tags, including:

- `email_service` - the pubkey of a email service that implements this protocol.
- `email_hash` - the sha256 hash of the user's email.
- `email_ciphertext` - the user's email encrypted to `email_service` using nip 44.

This prevents the signer from learning the email of the user, while also enabling it to pass the email along to the email service.

Each signer must then explicitly accept or (optionally) reject the share:

```typescript
{
  "kind": 28350,
  "pubkey": "<signer pubkey>",
  "content": nip44_encrypt([
    ["method", "register/result"],
    ["status", "<error|pending|ok>"],
    ["message", "<human readable message>"],
    ["e", "<register/request event id>"],
  ]),
  "tags": [
    ["p", "<client pubkey>"],
  ],
}
```

This event MUST include `status` and `message` in its private tags. If a `email` is included, signers MUST validate ownership it (see below), in the meantime returning `pending` with a helpful `message`. When the email has been validated, the signer must then send another ack for the same event with `status=ok`.

If a session exists with the same `email_hash` or `pubkey`, signers SHOULD create a new session rather than replacing the old one or rejecting the new one.

The same signer MUST NOT be used multiple times for multiple shares of the same key.

### Email Validation

In order to validate a user's email, a signer must send a `validate/request` event to the given `email service`:

```typescript
{
  "kind": 28350,
  "pubkey": "<signer pubkey>",
  "content": nip44_encrypt([
    ["method", "validate/request"],
    ["client_pubkey", "<client pubkey>"],
    ["email_ciphertext", "<nip44 encrypted user email>"],
  ]),
  "tags": [
    ["p", "<email service pubkey>"],
  ],
}
```

This event must include a `client_pubkey` tag in order to allow email services to decrypt `email_ciphertext` and accurately batch requests.

When the user has completed the verification process, the email service must send a `validate/result` to each signer. The email service MAY send a "pending" response in the meantime, and SHOULD send an "error" response if the email could not be validated for any reason.

```typescript
{
  "kind": 28350,
  "pubkey": "<email service pubkey>",
  "content": nip44_encrypt([
    ["method", "validate/result"],
    ["status", "<error|pending|ok>"],
    ["message", "<human readable message>"],
    ["client_pubkey", "<client pubkey>"],
  ]),
  "tags": [
    ["p", "<signer pubkey>"],
  ],
}
```

### Signing

When a client wants to sign an event, it must choose at least `threshold` signers and send a `sign/request` event to each signer:

```typescript
{
  "kind": 28350,
  "pubkey": "<client pubkey>",
  "content": nip44_encrypt([
    ["method", "sign/request"],
    ["session", "<JSON-encoded sign session package>"],
    ["event", "<JSON-encoded event to be signed>"],
  ]),
  "tags": [
    ["p", "<signer pubkey>"],
  ],
}
```

The `session` tag contains a JSON-encoded `sign session package` object:

```typescript
{
  gid: string            // Group ID (32 byte hash of group data)
  sid: string            // Session ID (32 byte hash of session params)
  content: string | null // Optional metadata
  stamp: number          // Unix timestamp
  type: string           // Session type (e.g., "nostr-event")
  hashes: string[][]     // Array of sighash vectors: [sighash, ...tweaks]
  members: number[]      // Array of participating member indices
}
```

The signer must then look up the corresponding registration and respond with a `sign/result` event:

```typescript
{
  "kind": 28350,
  "pubkey": "<signer pubkey>",
  "content": nip44_encrypt([
    ["method", "sign/result"],
    ["psig", "<JSON-encoded partial signature package>"],
    ["e", "<sign/request event id>"],
  ]),
  "tags": [
    ["p", "<client pubkey>"],
  ],
}
```

The `psig` tag contains a JSON-encoded `partial signature package` object:

```typescript
{
  idx: number       // Signer index
  pubkey: string    // Signer's hex public key (compressed, 33 bytes)
  sid: string       // Session ID
  psigs: string[][] // Array of partial signatures: [sighash, partial_signature]
}
```

The client then combines the partial signatures into an aggregated signature which can be applied to the event.

### Session deletion

When a user wishes to log out of any active signing sessions, their client can send a `logout/request` event to all signers:

```typescript
{
  "kind": 28350,
  "pubkey": "<client pubkey>",
  "content": nip44_encrypt([
    ["method", "logout/request"],
    ["revoke", "<current|others|all>"],
  ]),
  "tags": [
    ["p", "<signer pubkey>"],
  ],
}
```

The client MUST include a private `revoke` tag which indicates whether the user wants to sign out of the current session only, other sessions, or all sessions connected to the user's `pubkey`. Signers MUST delete all key material from their database. Clients SHOULD inform users that this action makes key recovery impossible.

### Recovery

To recover the user's original `secret key` by email alone without access to an active `client key`, a client must `sha256` hash the user's email and generate a new single-use `recovery key`. It then sends a `recover/request` event to each signer:

```typescript
{
  "kind": 28350,
  "pubkey": "<recovery pubkey>",
  "content": nip44_encrypt([
    ["method", "recover/request"],
    ["email_hash", "<sha256 hash of user email>"],
  ]),
  "tags": [
    ["p", "<signer pubkey>"],
  ],
}
```

Each signer then finds any sessions that were registered with `email_hash`. If multiple sessions exist, the signer should send a `recover/select` event back to the client in order to allow the user to select which account to recover:

```typescript
{
  "kind": 28350,
  "pubkey": "<signer pubkey>",
  "content": nip44_encrypt([
    ["method", "recover/select"],
    ["pubkey", "<pubkey 1>"],
    ["pubkey", "<pubkey 2>"],
    ["e", "<kind recover/request event id>"],
  ]),
  "tags": [
    ["p", "<recovery pubkey>"],
  ],
}
```

The client should then display these options to the user and re-send a `recover/share` with an additional `pubkey` tag specifying the pubkey to recover.

Each signer must then encrypt the matching `share` and `group` to the `email_service` provided when the share was registered and send them, along with their corresponding `email_ciphertext`, to the `email_service` using a `recover/share` event:

```typescript
{
  "kind": 28350,
  "pubkey": "<signer pubkey>",
  "content": nip44_encrypt([
    ["method", "recover/share"],
    ["count", "<number of signers>"],
    ["recovery_pubkey", "<recovery pubkey>"],
    ["email_ciphertext", "<nip44 encrypted user email>"],
    ["share_ciphertext", "<encrypted hex encoded share package>"],
    ["group_ciphertext", "<encrypted hex encoded group package>"],
  ]),
  "tags": [
    ["p", "<email service pubkey>"],
  ],
}
```

The email service waits until `count` shares have been received and sends the group and all shares to the decrypted `email` in the following format:

`base58(group_ciphertext + share_ciphertext * n)`

The user can copy this payload into their recovery client, which uses the `recovery key` the user generated at the beginning of the process to decrypt all shares and reconstitute the user's secret key.

### Login

To log in to a user's existing signing session by email alone, a client must request the user's email and get its `sha256` hash. Then, it must generate a new single-use `login key`. It then sends this to each signer using a `login/request` event:

```typescript
{
  "kind": 28350,
  "pubkey": "<login pubkey>",
  "content": nip44_encrypt([
    ["method", "login/request"],
    ["email_hash", "<sha256 hash of user email>"],
  ]),
  "tags": [
    ["p", "<signer pubkey>"],
  ],
}
```

Each signer then finds any sessions that were registered with `email_hash`. If multiple sessions exist, the signer should send a `login/select` event back to the client in order to allow the user to select which account to recover:

```typescript
{
  "kind": 28350,
  "pubkey": "<signer pubkey>",
  "content": nip44_encrypt([
    ["method", "login/select"],
    ["pubkey", "<pubkey 1>"],
    ["pubkey", "<pubkey 2>"],
    ["e", "<kind login/request event id>"],
  ]),
  "tags": [
    ["p", "<login pubkey>"],
  ],
}
```

The client should then display these options to the user and re-send a `login/request` with an additional `pubkey` tag specifying the pubkey to recover.

Each signer then generates a single-use expiring OTP and associates it with the selected share. The signer then encrypts the OTP and sends it to the `email_service` using a `login/share` event:

```typescript
{
  "kind": 28350,
  "pubkey": "<signer pubkey>",
  "content": nip44_encrypt([
    ["method", "login/share"],
    ["count", "<number of signers>"],
    ["login_pubkey", "<login pubkey>"],
    ["otp_ciphertext", "<encrypted OTP>"],
    ["email_ciphertext", "<nip44 encrypted user email>"],
  ]),
  "tags": [
    ["p", "<email service pubkey>"],
  ],
}
```

The email service waits until `count` messages have been received and sends signer pubkeys and OTP codes to the user in the following format:

`base58(pubkey1:otp1_ciphertext,pubkey2:otp2_ciphertext)`

The user can then copy the payload into their client, which generates a fresh `client secret`, decrypts all OTPs, and sends another `client/login` event to each signer:

```typescript
{
  "kind": 28350,
  "pubkey": "<client pubkey>",
  "content": nip44_encrypt([
    ["method", "login/confirm"],
    ["email_hash", "<sha256 of user email>"],
    ["otp", "<otp code>"],
  ]),
  "tags": [
    ["p", "<signer pubkey>"],
  ],
}
```

The signer must then explicitly accept or (optionally) reject the OTP using a `LOGIN_RESULT` event. If the OTP is accepted, the signer MUST include the hex-encoded `group` package in the event, and make a copy of the existing session authorizing the given `client pubkey`.

```typescript
{
  "kind": 28350,
  "pubkey": "<signer pubkey>",
  "content": nip44_encrypt([
    ["method", "login/result"],
    ["status", "<error|pending|ok>"],
    ["message", "<error|pending|ok>"],
    ["group", "<hex encoded group package>"],
    ["e", "<kind login/confirm event id>"],
  ]),
  "tags": [
    ["p", "<client pubkey>"],
  ],
}
```

## Threat model

There are a few denial-of-service attack vectors and privacy leaks in this spec, which are to a certain extent unavoidable with email-based login and recovery. Keep these in mind when directing users to use this or another approach for login.

- Anyone can initiate a recovery or login flow for any email address, spamming the mailer service and the end user's email inbox. This is mitigated by using one-off client keys to sign messages, such that neither a user's pubkey nor email is visible. This attack is only possible if an attacker knows which bunkers a given email is registered with.
- Malicious email services can block registration, recovery, and login if they choose not to send messages to certain emails.
- Signers have access to user pubkeys and email services have access to user emails, but neither have access to both, preventing trivial correlation. However, email hashes are not salted, so it is possible to break the hashes given a list of valid emails.
- `login/select` and `recover/select` can leak the association between an email and a pubkey to an attacker that is able to provide a valid email address. This can be mitigated by rate-limiting login/recover events, but is something that users should be informed about in case they want to keep their email/pubkey link private. This attack vector only exists for users who have associated multiple pubkeys with a given email.
