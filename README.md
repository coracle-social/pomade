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
      idx: number         // commit index
      binder_sn: string   // 32 byte hex string
      hidden_sn: string   // 32 byte hex string
      seckey: string      // 32 byte hex string
    }
    group: {
      commits: Array<{
        idx: number       // commit index
        pubkey: string    // 33 byte hex string
        hidden_pn: string // 33 byte hex string
        binder_pn: string // 33 byte hex string
      }>
      group_pk: string    // 33 byte hex string
      threshold: number   // integer signing threshold
    }
  },
}
```

Each signer must then explicitly accept or (optionally) reject the share:

```typescript
{
  method: "register/result"
  payload: {
    status: "ok" | "error" // whether registration succeeded
    message: string        // a human-readable error/success message
    prev: string           // 32 byte hex id of request event
  }
}
```

If a session exists with the same pubkey, signers SHOULD create a new session rather than replacing the old one or rejecting the new one.

The same signer MUST NOT be used multiple times for multiple shares of the same key. The same client key MUST NOT be used multiple times for different sessions.

### Setting a Recovery Method

Users MAY set a recovery method by sending a `setRecoveryMethod/request` to the signers for a given session.

```typescript
{
  method: "setRecoveryMethod/request"
  payload: {
    mailer: string         // 32 byte hex pubkey of mailer service
    inbox: string          // string identifying the user to the mailer service
    callback_url?: string  // optional callback url to send users to
  }
}
```

A recovery method MUST be set within a short time (e.g., 5 minutes) of registration. Otherwise, if an attacker is able to provider their own recovery method a compromised session can lead to key compromise. Both `mailer` and `inbox` are bound to the session in advance of recovery to prevent an attacker from providing a MITM mailer.

A recovery method may be any out of band communcation method in which the user is uniquely identifiable by a non-sensitive token (for example, an email address).

In order to validate a user's inbox, signers must generate an OTP and send it to the given `mailer`:

```typescript
{
  method: "setRecoveryMethod/challenge"
  payload: {
    otp: string            // 6+ digit one time password
    inbox: string          // the user's email address or other inbox identifier
    pubkey: string         // 32 byte hex public key of the user
    threshold: number      // number of signers that need to validate the email (not the signing threshold)
    callback_url?: string  // callback url provided in setRecoveryMethod/request
  }
}
```

The mailer then combines all the signer pubkeys and provided OTPs into a single base58 encoded url string and includes it in the message to the user:

```typescript
base58encode("<pubkey1>=<otp1>&<pubkey2>=<otp2>")
```

The mailer MAY include a link in the message by appending the base58 encoded challenge to the `callback_url`. This does not constitute a man-in-the-middle attack, because the client secret is held by the application the user is using to execute the recovery flow.

Once it receives the challenge, the user's client should parse it and send each OTP to the correct signer:

```typescript
{
  method: "setRecoveryMethod/finalize"
  payload: {
    otp: string  // 6+ digit one time password provided for the signer
  }
}
```

The signer must then indicate whether the flow was successful:

```typescript
{
  method: "setRecoveryMethod/finalize/result"
  payload: {
    status: "ok" | "error" // whether the flow was successful
    message: string        // human-readable error/success message
    prev: string           // 32 byte hex encoded setRecoveryMethod/finalize event id
  }
}
```

### Signing

When a client wants to sign an event, it must choose at least `threshold` signers and send a request to each signer:

```typescript
{
  method: "sign/request"
  payload: {
    content?: string  // optional metadata about the signing session
    hashes: string[]  // array of sighash vectors: [sighash, ...tweaks] for each message to sign
    members: number[] // array of participating member indices (commit indices)
    stamp: number     // unix timestamp when the session was created
    type: string      // session type identifier (e.g., "nostr-event", "message")
    gid: string       // group id: 32 byte hash identifying the signing group
    sid: string       // session id: 32 byte hash uniquely identifying this signing session
  }
}
```

The signer must then look up the session corresponding to the client's pubkey and respond:

```typescript
{
  method: "sign/result"
  payload: {
    request: {
      idx: number            // signer index
      pubkey: string         // signer's hex public key (compressed, 33 bytes)
      sid: string            // session id
      psigs: string[][]      // array of partial signatures: [sighash, partial_signature]
      status: "ok" | "error" // whether the flow was successful
      message: string        // human-readable error/success message
      prev: string           // 32 byte hex encoded setRecoveryMethod/finalize event id
    }
  }
}
```

The client then combines the partial signatures into an aggregated signature which can be applied to the event.

### Encryption/Decryption

In order asymmetrically encrypt or decrypt a payload, a shared secret must be derived. Encryption/decryption can't be done in a directly multiparty way, so this spec instead supports conversation key generation and sharing.

When a client wants to encrypt or an event, it must choose at least `threshold` signers and as for a shared secret:

```typescript
{
  method: "ecdh/request"
  payload: {
    idx: number       // signer index
    members: number[] // array of participating member indices (commit indices)
    ecdh_pk: string   // 32 byte hex encoded counterparty pubkey
  }
}
```

The signer must then look up the session corresponding to the client's pubkey and respond:

```typescript
{
  method: "ecdh/result"
  payload: {
    result?: {
      idx: number          // signer index
      keyshare: string     // shared secret for use in encryption
      members: number[]    // array of participating member indices (commit indices)
      ecdh_pk: string      // 32 byte hex encoded counterparty pubkey
    },
    status: "ok" | "error" // whether the flow was successful
    message: string        // human-readable error/success message
    prev: string           // 32 byte hex encoded setRecoveryMethod/finalize event id
  }
}
```

The client then combines the results into a shared secret which can be used for encryption and decryption with the given counterparty.

```typescript
import {extract} from "@noble/hashes/hkdf.js"
import {sha256} from "@noble/hashes/sha2.js"
import {hexToBytes, bytesToHex} from "@noble/hashes/utils.js"

const textEncoder = new TextEncoder()

const rawSharedSecret = hexToBytes(Lib.combine_ecdh_pkgs(results).slice(2))
const nostrConversationKey = bytesToHex(extract(sha256, rawSharedSecret, textEncoder.encode("nip44-v2")))
```

### Recovery

To recover the user's original `secret key` by email alone without access to an active `client key`, a client can send a recovery request to all known signers using a fresh client key:

```typescript
{
  method: "recover/request"
  payload: {
    inbox: string // the user's inbox identifier
    pubkey?: string // the user's pubkey (optional, useful if multiple pubkeys are associated with a single inbox)
    callback_url?: string // optional callback url to send users to
  }
}
```

Each signer then finds any sessions that were registered with the provided `inbox` and send an OTP to each one. If multiple sessions exist for a single inbox/pubkey pair, the signer should pick the most recently active

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

## Implementation

This implementation uses @frostr/bifrost for all cryptographic functionality.

## Threat model

There are a few denial-of-service attack vectors and privacy leaks in this spec, which are to a certain extent unavoidable with email-based login and recovery. Keep these in mind when directing users to use this or another approach for login.

- Anyone can initiate a recovery or login flow for any email address, spamming the mailer service and the end user's email inbox. This is mitigated by using one-off client keys to sign messages, such that neither a user's pubkey nor email is visible. This attack is only possible if an attacker knows which bunkers a given email is registered with.
- Malicious mailers can block registration, recovery, and login if they choose not to send messages to certain emails.
- Signers have access to user pubkeys and mailers have access to user emails, but neither have access to both, preventing trivial correlation. However, email hashes are not salted, so it is possible to break the hashes given a list of valid emails.
- `login/select` and `recover/select` can leak the association between an email and a pubkey to an attacker that is able to provide a valid email address. This can be mitigated by rate-limiting login/recover events, but is something that users should be informed about in case they want to keep their email/pubkey link private. This attack vector only exists for users who have associated multiple pubkeys with a given email.
