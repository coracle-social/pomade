# Pomade

Nostr uses secp256k1 keypairs which are used to sign, encrypt, and decrypt messages. Keys are GREAT. However, they are very hard to understand, secure, and use for non-nerds. This project has several goals:

- Secure key storage using Shamir Secret Sharing via FROST (Schnorr) threshold signatures.
- The ability for users to recover their secret key using only an email.
- Non-interactive signing of messages.

WARNING: this project should be considered ALPHA, and not ready for use in production. Neither the protocol nor the code has been audited. There could be fatal flaws resulting in key loss, theft, denial of service, or metadata leakage. Use this at your own risk.

## Components

### Client

A _client_ is an application that can be trusted to (temporarily) handle key material and request signatures on a user's behalf. A client identifies itself to signers by a freshly generated session-specific nostr public key.

### Signer

A _signer_ is a headless application that can be trusted to store key shares and collaborate in building threshold signatures. A signer is identified by a nostr public key. Communication is brokered following NIP 65.

### Mailer

A _mailer_ is a headless application that can be trusted to send messages containing one time passwords to users, but not to access key material. Communication is brokered following NIP 65.

## Protocol Overview

In order to protect message metadata, this protocol uses a single event kind, `28350`, for all requests. These events are `p`-tagged to the recipient, and their `content` is set to the nip44-encrypted JSON-encoded message. Massages contain a `method` that determines the semantics of its `payload`.

```typescript
{
  kind: 28350,
  pubkey: author,
  content: nip44_encrypt({method, payload}),
  tags: [["p", recipient]],
  // other fields
}
```

### Registration

To create a new signing session, a client must first generate a new `client secret` which it will use to communicate with signers. This key MUST NOT be re-used, and MUST be distinct from the user's pubkey.

The client then shards the user's `secret key` using FROST and registers each share with a different signer by creating a `register/request` event:

```typescript
{
  method: "register/request"
  payload: {
    share: {
      idx: number // commit index
      binder_sn: string // 32 byte hex string
      hidden_sn: string // 32 byte hex string
      seckey: string // 32 byte hex string
    }
    group: {
      commits: Array<{
        idx: number // commit index
        pubkey: string // 33 byte hex string
        hidden_pn: string // 33 byte hex string
        binder_pn: string // 33 byte hex string
      }>
      group_pk: string // 33 byte hex string
      threshold: number // integer signing threshold
    }
  },
}
```

  registerResult: z.object({
    status: z.enum(Object.values(Status)),
    message: z.string(),
    prev: hex32,
  }),

Each signer must then explicitly accept or (optionally) reject the share:

```typescript
{
  method: "register/result"
  payload: {
    status: "ok" | "error"
    message: string
    prev: string // 32 byte hex id of request event
  }
}
```

If a session exists with the same pubkey, signers SHOULD create a new session rather than replacing the old one or rejecting the new one.

The same signer MUST NOT be used multiple times for multiple shares of the same key. The same client key MUST NOT be used multiple times for different sessions.

### Setting a Recovery Method

Users MAY set a recovery method by sending a `

In order to validate a user's email, a signer must send a `validate/request` event to the given `mailer`:

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
    ["p", "<mailer pubkey>"],
  ],
}
```

This event must include a `client_pubkey` tag in order to allow mailers to decrypt `email_ciphertext` and accurately batch requests.

When the user has completed the verification process, the mailer must send a `validate/result` to each signer. The mailer MAY send a "pending" response in the meantime, and SHOULD send an "error" response if the email could not be validated for any reason.

```typescript
{
  "kind": 28350,
  "pubkey": "<mailer pubkey>",
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
    ["p", "<mailer pubkey>"],
  ],
}
```

The mailer waits until `count` shares have been received and sends the group and all shares to the decrypted `email` in the following format:

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
    ["p", "<mailer pubkey>"],
  ],
}
```

The mailer waits until `count` messages have been received and sends signer pubkeys and OTP codes to the user in the following format:

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

## Implementation

This implementation uses @frostr/bifrost for all cryptographic functionality.

## Threat model

There are a few denial-of-service attack vectors and privacy leaks in this spec, which are to a certain extent unavoidable with email-based login and recovery. Keep these in mind when directing users to use this or another approach for login.

- Anyone can initiate a recovery or login flow for any email address, spamming the mailer service and the end user's email inbox. This is mitigated by using one-off client keys to sign messages, such that neither a user's pubkey nor email is visible. This attack is only possible if an attacker knows which bunkers a given email is registered with.
- Malicious mailers can block registration, recovery, and login if they choose not to send messages to certain emails.
- Signers have access to user pubkeys and mailers have access to user emails, but neither have access to both, preventing trivial correlation. However, email hashes are not salted, so it is possible to break the hashes given a list of valid emails.
- `login/select` and `recover/select` can leak the association between an email and a pubkey to an attacker that is able to provide a valid email address. This can be mitigated by rate-limiting login/recover events, but is something that users should be informed about in case they want to keep their email/pubkey link private. This attack vector only exists for users who have associated multiple pubkeys with a given email.
