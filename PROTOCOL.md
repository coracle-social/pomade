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

### Setting a Recovery Method

Users MAY set a recovery method by sending a `recoveryMethod/set` to the signers for a given session.

```typescript
{
  method: "recoveryMethod/set"
  payload: {
    mailer: string         // 32 byte hex pubkey of mailer service
    inbox: string          // string identifying the user to the mailer service
    callback_url?: string  // optional callback url to send users to
  }
}
```

Signers must respond as follows:

```typescript
{
  method: "recoveryMethod/set/result"
  payload: {
    ok: boolean // whether the flow was successful
    message: string // human-readable error/success message
    prev: string // 32 byte hex encoded recoveryMethod/set event id
  }
}
```

A recovery method MUST be set within a short time (e.g., 5 minutes) of registration. Otherwise, if an attacker is able to provide their own recovery method a compromised session can lead to key compromise. Both `mailer` and `inbox` are bound to the session in advance of recovery to prevent an attacker from providing a MITM mailer.

A recovery method may be any out of band communication method in which the user is uniquely identifiable by a non-sensitive token (for example, an email address).

In order to validate a user's inbox, signers must generate an OTP and send it to the given `mailer`:

```typescript
{
  method: "recoveryMethod/challenge"
  payload: {
    otp: string            // 6+ digit one time password
    client: string         // 32 byte hex public key of the user's client (for batching emails)
    inbox: string          // the user's email address or other inbox identifier
    pubkey: string         // 32 byte hex public key of the user
    threshold: number      // number of signers that need to validate the email (not the signing threshold)
    callback_url?: string  // callback url provided in recoveryMethod/set
  }
}
```

The mailer then combines all the signer pubkeys and provided OTPs into a single base58 encoded url string and includes it in the message to the user:

```typescript
base58encode("<pubkey1>=<otp1>&<pubkey2>=<otp2>")
```

The mailer MAY include a link in the message by appending the base58 encoded challenge to the `callback_url`. This does not constitute a man-in-the-middle attack, because the client secret is held by the application the user is using to execute the recovery flow.

Once the user's client receives the challenge, it should parse it and send each OTP to the correct signer:

```typescript
{
  method: "recoveryMethod/finalize"
  payload: {
    otp: string // 6+ digit one time password provided for the signer
  }
}
```

The signer must then indicate whether the flow was successful:

```typescript
{
  method: "recoveryMethod/finalize/result"
  payload: {
    ok: boolean // whether the flow was successful
    message: string // human-readable error/success message
    prev: string // 32 byte hex encoded recoveryMethod/finalize event id
  }
}
```

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

### Recovery

To recover access to the user's secret by email alone without access to an active `client key`, a client can send a recovery request to all known signers using a fresh client key. This recovery request can be either a `login` in which case the signer will create a new session for the user's client key, or a `recovery` in which case the signer will return the user's key shares.

```typescript
{
  method: "recovery/start"
  payload: {
    type: "login" | "recovery"  // whether to return the shares or create a new session on completion
    inbox: string               // the user's inbox identifier
    pubkey?: string             // the user's pubkey (optional, useful if multiple pubkeys are associated with a single inbox)
    callback_url?: string       // optional callback url to send users to
  }
}
```

Signers then respond:

```typescript
{
  method: "recovery/start/result"
  payload: {
    ok: boolean // whether the flow was successful
    message: string // human-readable error/success message
    prev: string // 32 byte hex encoded recovery/start event id
  }
}
```

Each signer then finds any sessions that were registered with the provided `inbox` and sends its `client`, `threshold`, and a newly generated `otp` to its `mailer` service.

```typescript
{
  method: "recovery/challenge"
  payload: {
    idx: number           // the index of the signer's share
    inbox: string         // the user's inbox identifier
    pubkey: string        // the user's pubkey
    items: {
      otp: string         // a one-time code unique to this item
      client: string      // 32 byte hex-encoded client pubkey
      threshold: number   // minimum number of shares needed to recover the user's key
    }[],
    callback_url?: string // optional callback url to send users to
  }
}
```

Because a user may have sessions across a disjunct set of signers, some of which may fail to forward their session info to the mailer, mailers will have to make a best-effort attempt to figure out which session to recover from. It can do this by grouping by `client`. If the number of peers that have responded is equal to the `threshold` for those options, the mailer can send a recovery message. If the recovery type is `login`, the mailer must sort signer pubkeys based on `idx` so that the client can send the correct requests to the correct signers.

Signers should be careful to send items to the `mailer` designated by the user when the recovery method was registered. If multiple pubkeys have been registered for a single recovery method, it should send a separate recovery OTP to mailers for each pubkey. The mailer MAY then re-batch by `inbox` so that the user only receives one message with the option to restore any one of the registered pubkeys.

Once `threshold` signers have sent OTPs to a `mailer` for a given pubkey/inbox combination, the `mailer` must then combine these OTPs into a single challenge as follows:

```typescript
base58encode("<pubkey1>=<otp1>&<pubkey2>=<otp2>")
```

The mailer MAY include a link in the message by appending the base58 encoded challenge to the `callback_url`. This does not constitute a man-in-the-middle attack, because the client secret is held by the application the user is using to execute the recovery flow.

Once the user's client receives the challenge, it should parse it and send each OTP to the correct signer:

```typescript
{
  method: "recovery/finalize"
  payload: {
    otp: string // 6+ digit one time password provided for the signer
  }
}
```

_IMPORTANT_: In order for recovery completion to be valid, it MUST be signed by the **same client pubkey** that initiated the recovery flow. Signers MUST also invalidate OTPs after a small number of attempts to prevent brute force attacks. OTPs MUST be invalidated after a short period of time as well (e.g., 15 minutes).

If this was a `login` flow, the signer should create a new session with the same group/share using the newly-generated client key, and NOT return them. If this was a `recovery` flow, the signer must return the `group` and `commit` originally generated on the user's client:

```typescript
{
  method: "recovery/finalize/result"
  payload: {
    share?: {
      idx: number // commit index
      binder_sn: string // 32 byte hex string
      hidden_sn: string // 32 byte hex string
      seckey: string // 32 byte hex string
    }
    group?: {
      commits: Array<{
        idx: number // commit index
        pubkey: string // 33 byte hex string
        hidden_pn: string // 33 byte hex string
        binder_pn: string // 33 byte hex string
      }>
      group_pk: string // 33 byte hex string
      threshold: number // integer signing threshold
    }
    ok: boolean // whether the flow was successful
    message: string // human-readable error/success message
    prev: string // 32 byte hex encoded recovery/finalize event id
  }
}
```

The client can then reconstruct the user's secret key from the `group` and `share`.

```typescript
import {Lib} from "@frostr/bifrost"

Lib.recover_secret_key(group, shares)
```

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
    sessions: {
      client: string         // 32 byte hex encoded client pubkey (doubles as session id)
      inbox?: string         // the user's recovery method
      created_at: number     // seconds-resolution timestamp when the session was created
      last_activity: number  // seconds-resolution timestamp when the session was last used
    }[],
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

## Implementation

This implementation uses @frostr/bifrost for all cryptographic functionality.

## Threat model

Signers are the most trusted party in this setup. It is assumed that they are run by reputable people, and carefully selected by clients based on this reputation. If `threshold` signers collude, they are necessarily able to steal key material. This can be mitigated by having clients store one key share, reducing the surface area of attack, but this comes at the trade-off of making recovery more fragile.

Mailers are trusted to the extent that they have access to user metadata (e.g. linking nostr pubkeys, user emails, and client pubkeys which can be used for traffic analysis), but are not capable of executing a man-in-the-middle attack. In addition, since recovery is triggered using only publicly available information, anyone can initiate a recovery flow, spamming the mailer service and the end user's inbox.

However, both signers and mailers have the ability to perform a denial-of-service attack by refusing to respond to messages or relay challenges to the user's `inbox`. User key shares are also held on servers accessible to the internet, which likely are running the same code, and so if one signer is vulnerable, all of them are.

For this reason, this scheme is not recommended for users who are capable of holding their own keys, but for users who are completely new to nostr and the concept of keys. Even still, clients that use this scheme should encourage their users to migrate to self-custody once they have established their value proposition. Other clients may choose to use this scheme for signing, but disable key recovery, opting for an encrypted backup instead.
