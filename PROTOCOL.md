# Pomade

Nostr uses secp256k1 keypairs which are used to sign, encrypt, and decrypt messages. Keys are GREAT. However, they are very hard to understand, secure, and use for non-nerds. This project has several goals:

- Secure key storage using Shamir Secret Sharing via FROST (Schnorr) threshold signatures.
- The ability for users to recover their secret key using only an email.
- Non-interactive signing of messages.

WARNING: this project should be considered ALPHA, and not ready for use in production. Neither the protocol nor the code has been audited. There could be fatal flaws resulting in key loss, theft, denial of service, or metadata leakage. Use this at your own risk.

## Components

### Client

A _client_ is an application that can be trusted to (temporarily) handle key material and request signatures on a user's behalf. A client identifies itself to signers using NIP 98 HTTP AUTH with a freshly generated session-specific nostr keypair (a `client key`).

### Signer

A _signer_ is a headless application identified by a URL (normalized, and including protocol, port, path, etc) that can be trusted to store key shares and collaborate in building threshold signatures. Communication happens directly via HTTPS JSON POST requests. Signers are also responsible for sending OTP codes over email in some flows.

## Protocol Overview

Requests are POSTed to specific URL paths over HTTP, and MUST be accompanied by the following headers:

- A `Content-Type` header containing `application/json`
- [NIP 98 HTTP AUTH](https://github.com/nostr-protocol/nips/blob/master/98.md) signed by either the `client key` or the `user key` depending on the endpoint.

Request and response schemas are described below.

### Registration

To create a new signing session, a client must first generate a new `client secret` which it will use to communicate with signers. This key MUST NOT be re-used for multiple sessions, and MUST be distinct from the user's pubkey.

The client then shards the user's `secret key` using FROST and registers each share with a different signer by sending a `register` request to the signer's URL.

Registration requests MUST include at least 20 bits of proof of work as defined in [NIP-13](https://github.com/nostr-protocol/nips/blob/master/13.md) in the NIP 98 authorization event. This requirement helps prevent spam and denial-of-service attacks against signers.

```typescript
POST /register
{
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
  recovery: boolean // whether recovery is enabled for this session
}
```

Each signer must then explicitly accept or (optionally) reject the share by returning a response:

```typescript
{
  ok: boolean // whether registration succeeded
  message: string // a human-readable error/success message
}
```

If a session exists with the same user pubkey, signers SHOULD create a new session rather than replacing the old one or rejecting the new one.

The same signer MUST NOT be used multiple times for multiple shares of the same key. The same client key MUST NOT be used multiple times for different sessions.

### Signing

When a client wants to sign an event, it runs a two-round FROST flow against at least `threshold` signers. Each signer commits to a fresh public nonce in round 1, keeps the matching secret nonce server-side only, and consumes it exactly once in round 2.

#### Round 1: Commit

The client sends one request per chosen signer to collect a fresh public nonce. The signer generates a fresh nonce, stores its secret half in memory keyed by a server-issued `commit_id`, and returns only the public half.

```typescript
POST /sign/commit
{
  members: number[] // member indexes for this session
}
```

The signer looks up the session for the authorized `client key` and responds:

```typescript
{
  ok: boolean          // whether the flow was successful
  message: string      // human-readable error/success message
  result?: {
    commit_id: string  // 32 byte hex, opaque server-issued handle for this commitment
    idx: number        // signer index
    pubkey: string     // signer's hex public key (compressed, 33 bytes)
    hidden_pn: string  // 33 byte hex string: fresh public nonce (hidden)
    binder_pn: string  // 33 byte hex string: fresh public nonce (binder)
  }
}
```

The `commit_id` is generated per signer, per round-1 call (not per session), is globally unique, and is treated by the client as an opaque handle that it routes back to the signer that issued it. The secret nonce is generated server-side and MUST NEVER be returned to the client or logged.

#### Round 2: Complete

The client builds the group signing context from the **fresh** public nonces collected in round 1, then sends one request per signer carrying the full participant public-nonce set, the chosen member set, and the signing request:

```typescript
POST /sign/complete
{
  commit_id: string          // the handle THIS signer returned in round 1
  request: {
    content: string | null   // optional metadata about the signing session
    hash: string[]           // a SINGLE sighash vector: [sighash, ...tweaks] (one message)
    members: number[]        // chosen member set; MUST match the round-1 members
    stamp: number            // unix timestamp when the session was created
    type: string             // session type identifier
    gid: string              // group id: 32 byte hash identifying the signing group
    sid: string              // session id: 32 byte hash uniquely identifying this signing session
  }
  pnonces: Array<{           // full participant public-nonce set for this permutation
    idx: number              // member index
    hidden_pn: string        // 33 byte hex string
    binder_pn: string        // 33 byte hex string
  }>
}
```

The signer looks up the secret nonce by `commit_id`, atomically consumes it, and responds:

```typescript
{
  ok: boolean          // whether the flow was successful
  message: string      // human-readable error/success message
  result?: {
    idx: number        // signer index
    pubkey: string     // signer's hex public key (compressed, 33 bytes)
    sid: string        // session id
    psig: string[]     // a single partial signature: [sighash, partial_signature]
  }
}
```

Each signer MUST validate the round-2 request before signing:

- The secret nonce MUST NOT be used more than once, and a fresh nonce signs exactly one message. The singular `hash` makes this structural: it is impossible to submit more than one message under a single fresh nonce, which is what prevents related-nonce key recovery. (Batching multiple messages under one fresh nonce would otherwise leak the secret share.) Failure to enforce single use can result in leaking key material.
- `pnonces` has exactly one entry per member in `request.members`, and every `idx` belongs to the group.
- The `pnonces` entry for the signer's own index matches the public nonce derived from the secret nonce stored under `commit_id`. This binds round 2 to the round-1 commitment and prevents a coordinator from substituting the signer's nonce.
- `gid` / `sid` verify against the group and request.
- `request.members` equals the member set stored with the commitment in round 1.

The signer rebuilds the same group signing context the client used — from the supplied fresh `pnonces`, applying an additive per-sighash nonce tweak — so the resulting partial signature combines identically. The response carries a single `psig` (a `[sighash, partial_signature]` pair) for the one message bound to this fresh nonce.

### Encryption/Decryption

In order asymmetrically encrypt or decrypt a payload, a shared secret must be derived. Encryption/decryption can't be done in a directly multiparty way, so this spec instead supports conversation key generation and sharing.

When a client wants to encrypt or an event, it must choose at least `threshold` signers and ask for a shared secret:

```typescript
POST /ecdh
{
  idx: number       // signer index
  members: number[] // array of participating member indices (commit indices)
  ecdh_pk: string   // 32 byte hex encoded counterparty pubkey
}
```

The signer must then look up the session corresponding to the authorized `client key` and respond:

```typescript
{
  ok: boolean              // whether the flow was successful
  message: string          // human-readable error/success message
  result?: {
    idx: number            // signer index
    keyshare: string       // shared secret for use in encryption
    members: number[]      // array of participating member indices (commit indices)
    ecdh_pk: string        // hex encoded counterparty pubkey
  }
}
```

The client then combines the results into a shared secret which can be used for encryption and decryption with the given counterparty.

```typescript
import {extract} from "@noble/hashes/hkdf.js"
import {sha256} from "@noble/hashes/sha2.js"
import {hexToBytes, bytesToHex} from "@noble/hashes/utils.js"
import {Lib} from "@frostr/bifrost"

const textEncoder = new TextEncoder()

const rawSharedSecret = hexToBytes(Lib.combine_ecdh_pkgs(results).slice(2))
const nostrConversationKey = bytesToHex(
  extract(sha256, rawSharedSecret, textEncoder.encode("nip44-v2")),
)
```

Note: signers MUST validate that `ecdh_pk` is a valid secp256k1 public key and MUST reject known-bad values such as the generator point `G`. If `ecdh_pk` is the generator point, the returned keyshare is effectively the signer's secret share itself, leading to key compromise.

### Setting a Recovery Method

Users MAY set a recovery method by sending a request to the signers for a given session.

Clients SHOULD validate the user's email address prior to sending it to the signers.

```typescript
POST /recovery/setup
{
  email: string          // user's email address
  password_hash: string  // argon2id(email || password, signer url, t=3, m=65536, p=2)
}
```

This event is authenticated by the `client key` used to sign the request, and should result in the email/password being associated with that session.

Signers must respond as follows:

```typescript
{
  ok: boolean      // whether the flow was successful
  message: string  // human-readable error/success message
}
```

A recovery method MUST be set within a short time (e.g., 15 minutes) of registration. Otherwise, if an attacker is able to provide their own recovery method a compromised session can lead to key compromise.

#### Password Authentication

In order to authenticate with a password, the client must calculate both `argon2id(email, signer url, t=3, m=65536, p=2)` and `argon2id(email || password, signer url, t=3, m=65536, p=2)` and send it in the `auth` payload as `{email_hash, password_hash}`.

Because it's not known at this point which signers hold the user's key shares, clients will have to send this payload to all known signers. In order to prevent signers from logging in to one another, the signer URL is used as the salt. The email is concatenated with the password before hashing to prevent cross-account correlation, ensuring that the same password produces different hashes for different users. Signers MUST validate that the `password_hash` sent on setup is a 32 byte hex string. Clients MUST ensure that users pick strong passwords.

#### One-Time Password Authentication

In order to authenticate with only an email address (in the case of the user forgetting their password), *each* signer has to authenticate the user independently (in order to avoid a MITM attack by a trusted email service that can lead to account compromise).

The client first chooses the signers it wishes to authenticate with and generates a unique two-digit integer OTP prefix for each one. It then sends a request for a one-time-password to each one:

```typescript
POST /challenge
{
  prefix: string              // random 2-digit OTP prefix
  email_hash: string          // argon2id(email, signer url, t=3, m=65536, p=2)
}
```

Signers must respond as follows:

```typescript
{
  ok: boolean      // MUST be true to prevent probing for email
  message: string  // MUST always be the same success message
}
```

In order to avoid leaking the user's email address to signers not already in posession of it, the email should be hashed using `argon2id(email, signer url, t=3, m=65536, p=2)`. This allows the signers that already know the user's email to look it up quickly, but makes it difficult to brute force it for others.

If this is used for recovery from an active session, the client should only send this request to the selected signers. If used for logging in after a password has been forgotten, it won't be known which signers hold the user's key shares, so clients will have to send this request to all known signers. As a result, if a user has multiple active sessions they may receive more than `total` OTPs. Clients should handle this by allowing the user to paste any number of OTPs, or by keeping track out of band which signers were used for a given email address.

Each signer sends an email to the user containing an OTP constructed by concatenating the client-provided prefix with at least 6 additional random digits. The user must then copy this into the requesting client.

The client must then identify which signer each OTP should be sent to using each code's prefix. OTPs MUST be invalidated after a single use, and MUST expire after a short time (but long enough for users to complete a given flow, e.g. 15 minutes).

#### Auth Payload

Below is a definition for payloads' `auth` key as used in login/recovery requests below which covers both password-based and OTP authentication:

```typescript
type AuthPayload =
  {
    email_hash: string        // argon2id(email, signer url, t=3, m=65536, p=2)
    password_hash: string     // argon2id(email || password, signer url, t=3, m=65536, p=2)
  } | {
    email_hash: string        // argon2id(email, signer url, t=3, m=65536, p=2)
    otp: string               // OTP obtained via email flow
  }
```

#### Session Data

Session data shows up a number of times in this protocol using the following definition:

```typescript
type SessionData = {
  pubkey: string          // 32 byte hex encoded user pubkey
  client: string          // 32 byte hex encoded client pubkey (doubles as session id)
  created_at: number      // seconds-resolution timestamp when the session was created
  last_activity: number   // seconds-resolution timestamp when the session was last used
  threshold: number       // signing threshold for the group
  total: number           // how many total signers are in the group
  idx: number             // the signer's index in the signing group
  email?: string          // recovery email
  deactivated_at?: number // seconds-resolution timestamp when the session was deactivated
}
```

### Login

To recover remote access to the user's secret by email alone, a client can send a request to all known signers using a fresh `client key` to initiate the login flow. This request is authenticated using the user's email and password/otp in the payload, in addition to NIP 98 HTTP AUTH. Subsequent requests MUST use the same `client key` in order to be considered valid.

```typescript
POST /login/start
{
  auth: AuthPayload
}
```

Signers should respond with a list of sessions that the client can log into:

```typescript
{
  ok: boolean              // whether the flow was successful
  message: string          // human-readable error/success message
  items?: SessionData[]
}
```

Clients should then select a `client` and notify the signer. Note that a single email may be associated with multiple user pubkeys, so clients should be prepared to show a screen allowing the user to choose which account to log in with.

```typescript
POST /login/select
{
  client: string
}
```

Signers should respond as follows:

```typescript
{
  ok: boolean              // whether the flow was successful
  message: string          // human-readable error/success message
  group?: {
    commits: Array<{
      idx: number          // commit index
      pubkey: string       // 33 byte hex string
      hidden_pn: string    // 33 byte hex string
      binder_pn: string    // 33 byte hex string
    }>
    group_pk: string       // 33 byte hex string
    threshold: number      // integer signing threshold
  }
}
```

Signers SHOULD NOT associate the new `client key` with the existing session, but instead should create an entirely new session with the authorized `client key`.

### Recovery

To recover a user's secret key by email alone, a client can send a request to all known signers to initiate a recovery flow. This request is authenticated using the user's email and password/otp in the payload in addition to NIP 98 HTTP AUTH. Subsequent requests MUST use the same `client key` in order to be considered valid.

```typescript
POST /recovery/start
{
  auth: AuthPayload
}
```

Signers should respond with a list of sessions that the client can recover from:

```typescript
{
  ok: boolean              // whether the flow was successful
  message: string          // human-readable error/success message
  items?: SessionData[]
}
```

Clients should then select a `client` and notify the signer. Note that a single email may be associated with multiple user pubkeys, so clients should be prepared to show a screen allowing the user to choose which account to recover.

```typescript
POST /recovery/select
{
  client: string
}
```

Signers should respond as follows:

```typescript
POST /recovery/result
{
  share?: {
    idx: number            // commit index
    binder_sn: string      // 32 byte hex string
    hidden_sn: string      // 32 byte hex string
    seckey: string         // 32 byte hex string
  }
  group?: {
    commits: Array<{
      idx: number          // commit index
      pubkey: string       // 33 byte hex string
      hidden_pn: string    // 33 byte hex string
      binder_pn: string    // 33 byte hex string
    }>
    group_pk: string       // 33 byte hex string
    threshold: number      // integer signing threshold
  }
  ok: boolean              // whether the flow was successful
  message: string          // human-readable error/success message
}
```

The client can then reconstitute the user's private key. This flow does not result in a new session being associated with the current `client key`.

### Session management

A user can request all active sessions for their pubkey by requesting them from all known signers (not just the ones the user is currently using). This message is authenticated using NIP 98 HTTP AUTH signed by **the user's own key**.

```typescript
POST /session/list
{}
```

Each signer must then respond with a list of sessions for the given user:

```typescript
{
  ok: boolean              // whether the flow was successful
  message: string          // human-readable error/success message
  items?: SessionData[]
}
```

These results may then be aggregated across all signers and displayed to the user.

### Session deactivation

If a user wishes to log out of a session without destroying the association between their email and secret share, they may send a session deactivation request to the signers in question. This will still allow email-based login and recovery, but revokes the validity of the `client` key. Clients SHOULD call this endpoint when logging a user out.

This message is authenticated using NIP 98 HTTP AUTH signed by **the user's own key**.

```typescript
POST /session/deactivate
{
  client: string // 32 byte hex encoded client pubkey
}
```

Signers should then respond by confirming the deactivation:

```typescript
{
  ok: boolean // whether the deactivation was successful
  message: string // human-readable error/success message
}
```

### Session deletion

If a user wishes to log out of a session *and* destroy the association between their email and secret share, they may send a session deletion request to the signers in question. This invalidates the `client` key, as well as the ability to use the session's share for login or recovery flows.

This message is authenticated using NIP 98 HTTP AUTH signed by **the user's own key**.

```typescript
POST /session/delete
{
  client: string // 32 byte hex encoded client pubkey
}
```

Signers should then respond by confirming the deletion:

```typescript
{
  ok: boolean // whether the deletion was successful
  message: string // human-readable error/success message
}
```

## Implementation Details

This implementation uses @frostr/bifrost as the standard for all cryptographic functionality.

If a user wishes to change their email or password for a given session, they should go through the `login` flow and set their new recovery information on the new session, optionally deleting the previous session afterwards.

## Threat model

It is assumed that signers are run by reputable people and carefully selected by clients based on this reputation. If `threshold` signers collude, they are necessarily able to steal key material.

Email providers are completely trusted since they can login to a user's session or even steal key material by requesting an OTP on a given user's behalf and using that to recover key material.

Signers and email service providers also have the ability to perform a denial-of-service attack by refusing to respond to messages or relay OTPs to the user.

User key shares and passwords are held on servers accessible to the internet. Signers running the same code are vulnerable to the same attacks. For this reason, multiple implementations are provided to keep keys safe even in the event of a successful attack.

This scheme is **not** recommended for users who are capable of holding their own keys, but for users who are completely new to nostr and the concept of keys. Clients that use this scheme should encourage their users to migrate to self-custody once they have established their value proposition, deleting signer sessions on migration.

Other clients may choose to use this scheme for signing but disable key recovery, opting for an encrypted backup instead.

Sessions SHOULD automatically expire after a certain period of inactivity (e.g., 30 days), limiting the window of exposure from a stolen client key. Signers SHOULD enforce rate limits on signing and ECDH requests to bound the damage an attacker can do with a compromised session and to prevent abuse. Signers SHOULD enforce rate limits on challenge requests per email to avoid denial-of-service attacks on a user's inbox.
