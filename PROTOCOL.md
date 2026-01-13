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

A _signer_ is a headless application that can be trusted to store key shares and collaborate in building threshold signatures. A signer is identified by a nostr public key. Communication is brokered following NIP 65. Signers are also responsible for sending OTP codes over email in some flows.

## Protocol Overview

In order to protect message metadata, this protocol uses a single event kind, `28350`, for all requests. These events are `p`-tagged to the recipient, and their `content` is set to the nip44-encrypted JSON-encoded message. Messages contain a `method` that determines the semantics of its `payload`.

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
    recovery: boolean // whether recovery is enabled for this session
  }
}
```

Each signer must then explicitly accept or (optionally) reject the share:

```typescript
{
  method: "register/result"
  payload: {
    ok: boolean // whether registration succeeded
    message: string // a human-readable error/success message
    prev: string // 32 byte hex id of request event
  }
}
```

If a session exists with the same pubkey, signers SHOULD create a new session rather than replacing the old one or rejecting the new one.

The same signer MUST NOT be used multiple times for multiple shares of the same key. The same client key MUST NOT be used multiple times for different sessions.

### Signing

When a client wants to sign an event, it must choose at least `threshold` signers and send a request to each signer:

```typescript
{
  method: "sign/request"
  payload: {
    request: {
      content: string | null   // optional metadata about the signing session
      hashes: string[][]       // array of sighash vectors: [sighash, ...tweaks] for each message to sign
      members: number[]        // array of participating member indices (commit indices)
      stamp: number            // unix timestamp when the session was created
      type: string             // session type identifier (e.g., "nostr-event", "message")
      gid: string              // group id: 32 byte hash identifying the signing group
      sid: string              // session id: 32 byte hash uniquely identifying this signing session
    }
  }
}
```

The signer must then look up the session corresponding to the client's pubkey and respond:

```typescript
{
  method: "sign/result"
  payload: {
    result?: {
      idx: number        // signer index
      pubkey: string     // signer's hex public key (compressed, 33 bytes)
      sid: string        // session id
      psigs: string[][]  // array of partial signatures: [sighash, partial_signature]
    }
    ok: boolean          // whether the flow was successful
    message: string      // human-readable error/success message
    prev: string         // 32 byte hex encoded sign/request event id
  }
}
```

The client then combines the partial signatures into an aggregated signature which can be applied to the event.

### Encryption/Decryption

In order asymmetrically encrypt or decrypt a payload, a shared secret must be derived. Encryption/decryption can't be done in a directly multiparty way, so this spec instead supports conversation key generation and sharing.

When a client wants to encrypt or an event, it must choose at least `threshold` signers and ask for a shared secret:

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
      idx: number            // signer index
      keyshare: string       // shared secret for use in encryption
      members: number[]      // array of participating member indices (commit indices)
      ecdh_pk: string        // hex encoded counterparty pubkey
    },
    ok: boolean              // whether the flow was successful
    message: string          // human-readable error/success message
    prev: string             // 32 byte hex encoded ecdh/request event id
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

### Setting a Recovery Method

Users MAY set a recovery method by sending a request to the signers for a given session.

Clients SHOULD validate the user's email address prior to sending it to the signers.

```typescript
{
  method: "recovery/setup"
  payload: {
    email: string          // user's email address
    password_hash: string  // argon2id(email || password, signer pubkey, t=3, m=65536, p=2)
  }
}
```

This event is authenticated by the `client key` used to sign the request, and should result in the email/password being associated with that session.

Signers must respond as follows:

```typescript
{
  method: "recovery/setup/result"
  payload: {
    ok: boolean      // whether the flow was successful
    message: string  // human-readable error/success message
    prev: string     // 32 byte hex encoded recovery/setup event id
  }
}
```

A recovery method MUST be set within a short time (e.g., 15 minutes) of registration. Otherwise, if an attacker is able to provide their own recovery method a compromised session can lead to key compromise.

#### Password Authentication

In order to authenticate with a password, the client must calculate both `argon2id(email, signer pubkey, t=3, m=65536, p=2)` and `argon2id(email || password, signer pubkey, t=3, m=65536, p=2)` and send it in the `auth` payload as `{email_hash, password_hash}`.

Because it's not known at this point which signers hold the user's key shares, clients will have to send this payload to all known signers. In order to prevent signers from logging in to one another, the signer pubkey is used as the salt. The email is concatenated with the password before hashing to prevent cross-account correlation, ensuring that the same password produces different hashes for different users. Signers MUST validate that the `password_hash` sent on setup is a 32 byte hex string. Clients MUST ensure that users pick strong passwords.

#### One-Time Password Authentication

In order to authenticate with only an email address (in the case of the user forgetting their password), *each* signer has to authenticate the user independently (in order to avoid a MITM attack by a trusted email service that can lead to account compromise).

The client first chooses the signers it wishes to authenticate with and generates a unique two-digit integer OTP prefix for each one. It then sends a request for a one-time-password to each one:

```typescript
{
  method: "challenge/request"
  payload: {
    prefix: string              // random 2-digit OTP prefix
    email_hash: string          // argon2id(email, signer pubkey, t=3, m=65536, p=2)
  }
}
```

In order to avoid leaking the user's email address to signers, the email should be hashed using `argon2id(email, signer pubkey, t=3, m=65536, p=2)`. This allows the signers that already know the user's email to look it up quickly, but makes it difficult to brute force it for others.

If this is used for recovery from an active session, the client should only send this request to the selected signers. If used for logging in after a password has been forgotten, it won't be known which signers hold the user's key shares, so clients will have to send this request to all known signers. As a result, if a user has multiple active sessions they may receive more than `total` OTPs. Clients should handle this by allowing the user to paste any number of OTPs, or by keeping track out of band which signers were used for a given email address.

Signers do not respond, since they should not indicate whether the user's email has been found anyway. Instead, each signer sends an email to the user containing an OTP constructed by concatenating the client-provided prefix with at least 6 additional random digits. The user must then copy this into the requesting client.

The client must then identify which signer each OTP should be sent to using each code's prefix. OTPs MUST be invalidated after a single use, and MUST expire after a short time (but long enough for users to complete a given flow, e.g. 15 minutes).

#### Auth Payload

Below is a definition for payloads' `auth` key, including either password-based or OTP authentication:

```typescript
type AuthPayload =
  {
    email_hash: string        // argon2id(email, signer pubkey, t=3, m=65536, p=2)
    password_hash: string     // argon2id(email || password, signer pubkey, t=3, m=65536, p=2)
  } | {
    email_hash: string        // argon2id(email, signer pubkey, t=3, m=65536, p=2)
    otp: string               // OTP obtained via email flow
  }
```

### Login

To recover remote access to the user's secret by email alone, a client can send a request to all known signers using a fresh `client key` to initiate the login flow. This request is authenticated using the user's email and password/otp. Subsequent requests MUST use the same `client key` in order to be considered valid.

```typescript
{
  method: "login/start"
  payload: {
    auth: AuthPayload
  }
}
```

Signers should respond with a list of sessions that the client can log into:

```typescript
{
  method: "login/options"
  payload: {
    items?: {
      pubkey: string         // 32 byte hex encoded user pubkey
      client: string         // 32 byte hex encoded client pubkey (doubles as session id)
      created_at: number     // seconds-resolution timestamp when the session was created
      last_activity: number  // seconds-resolution timestamp when the session was last used
      threshold: number      // signing threshold for the group
      total: number          // how many total signers are in the group
      idx: number            // the signer's index in the signing group
      email?: string         // recovery email
    }[],
    ok: boolean              // whether the flow was successful
    message: string          // human-readable error/success message
    prev: string             // 32 byte hex encoded login/start event id
  }
}
```

Clients should then select a `client` and notify the signer:

```typescript
{
  method: "login/select"
  payload: {
    client: string
  }
}
```

Signers should respond as follows:

```typescript
{
  method: "login/result"
  payload: {
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
    prev: string             // 32 byte hex encoded login/select event id
  }
}
```

Signers SHOULD NOT associate the new `client key` with the existing session, but instead should create an entirely new session with the key used to sign the request as the authorized `client key`.

### Recovery

To recover a user's secret key by email alone, a client can send a request to all known signers to initiate a recovery flow. This request is authenticated using the user's email and password/otp. Subsequent requests MUST use the same `client key` in order to be considered valid.

```typescript
{
  method: "recovery/start"
  payload: {
    auth: AuthPayload
  }
}
```

Signers should respond with a list of sessions that the client can recover from:

```typescript
{
  method: "recovery/options"
  payload: {
    items?: {
      pubkey: string         // 32 byte hex encoded user pubkey
      client: string         // 32 byte hex encoded client pubkey (doubles as session id)
      created_at: number     // seconds-resolution timestamp when the session was created
      last_activity: number  // seconds-resolution timestamp when the session was last used
      threshold: number      // signing threshold for the group
      total: number          // how many total signers are in the group
      idx: number            // the signer's index in the signing group
      email?: string         // recovery email
    }[],
    ok: boolean              // whether the flow was successful
    message: string          // human-readable error/success message
    prev: string             // 32 byte hex encoded login/start event id
  }
}
```

Clients should then select a `client` and notify the signer:

```typescript
{
  method: "recovery/select"
  payload: {
    client: string
  }
}
```

Signers should respond as follows:

```typescript
{
  method: "recovery/result"
  payload: {
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
    prev: string             // 32 byte hex encoded recovery/select event id
  }
}
```

The client can then reconstitute the user's private key. This flow does not result in a new session being associated with the current `client key`.

### Session management

A user can request all active sessions for their pubkey by requesting them from all known signers (not just the ones the user is currently using). This message is authenticated not based on the signing `client`, but based on a NIP 98 event signed by the user's own key with the signer's pubkey as the `u` tag and "session/list" as the `method`. The event's timestamp MUST be current to avoid replay attacks.

```typescript
{
  method: "session/list"
  payload: {
    auth: SignedEvent // NIP 98 auth event signed by user
  }
}
```

Each signer must then respond with a list of sessions for the given user:

```typescript
{
  method: "session/list/result"
  payload: {
    items: {
      pubkey: string         // 32 byte hex encoded user pubkey
      client: string         // 32 byte hex encoded client pubkey (doubles as session id)
      created_at: number     // seconds-resolution timestamp when the session was created
      last_activity: number  // seconds-resolution timestamp when the session was last used
      threshold: number      // signing threshold for the group
      total: number          // how many total signers are in the group
      idx: number            // the signer's index in the signing group
      email?: string         // recovery email
    }[]
    ok: boolean              // whether the flow was successful
    message: string          // human-readable error/success message
    prev: string             // 32 byte hex encoded session/list event id
  }
}
```

These results may then be aggregated across all signers and displayed to the user. If a user wishes to log out of a session, they may send a session deletion request to the signers in question. This message is authenticated not based on the signing `client`, but based on a NIP 98 event signed by the user's own key with the signer's pubkey as the `u` tag and "session/delete" as the `method`. The event's timestamp MUST be current to avoid replay attacks.

```typescript
{
  method: "session/delete"
  payload: {
    client: string // 32 byte hex encoded client pubkey
    auth: SignedEvent // NIP 98 auth event signed by user
  }
}
```

Signers should then respond by confirming the deletion:

```typescript
{
  method: "session/delete/result"
  payload: {
    ok: boolean // whether the deletion was successful
    message: string // human-readable error/success message
    prev: string // 32 byte hex encoded session/delete event id
  }
}
```

## Implementation Details

This implementation uses @frostr/bifrost for all cryptographic functionality.

If a user wishes to change their email or password for a given session, they should go through the `login` flow and set their new recovery information on the new session, optionally deleting the previous session afterwards.

## Threat model

It is assumed that signers are run by reputable people and carefully selected by clients based on this reputation. If `threshold` signers collude, they are necessarily able to steal key material.

Email providers are completely trusted since they can login to a user's session or even steal key material by requesting an OTP on a given user's behalf and using that to recover key material.

Signers and email service providers also have the ability to perform a denial-of-service attack by refusing to respond to messages or relay OTPs to the user.

User key shares and passwords are held on servers accessible to the internet which are likely running the same code, which means if one signer is vulnerable to a given attack, all of them are.

This scheme is **not** recommended for users who are capable of holding their own keys, but for users who are completely new to nostr and the concept of keys. Clients that use this scheme should encourage their users to migrate to self-custody once they have established their value proposition, deleting signer sessions on migration.

Other clients may choose to use this scheme for signing but disable key recovery, opting for an encrypted backup instead.
