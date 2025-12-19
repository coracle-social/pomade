# Pomade Client Integration Guide

This guide provides complete documentation and examples for integrating the Pomade Client into your application. Pomade enables secure threshold signature schemes for Nostr keys with email-based recovery.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Core Concepts](#core-concepts)
- [Configuration](#configuration)
- [Registration](#registration)
- [Signing Events](#signing-events)
- [Encryption (ECDH)](#encryption-ecdh)
- [Recovery Methods](#recovery-methods)
- [Account Recovery](#account-recovery)
- [Session Management](#session-management)
- [Error Handling](#error-handling)
- [Best Practices](#best-practices)

## Prerequisites

Before integrating Pomade, ensure you have:

1. **Running Signer Services**: At least 2-3 signer services running and accessible via Nostr relays. These **must** be run by multiple independent parties who are not likely to collude to steal user keys.
2. **Running Mailer Service**: A mailer service configured to send validation/recovery emails. You may want to run this yourself if you want control over how emails are branded. It's also possible to create a mailer that uses a recovery method other than email.
3. **Nostr Relay Access**: Configured relays that both your client and signers can access
4. **User's Nostr Key**: A nostr private key (either existing or newly generated)

## Core Concepts

### Components

- **Client**: Your application that requests signatures on behalf of users. Each session uses a temporary session-specific key.
- **Signer**: Headless services that store key shares and collaborate to create threshold signatures. Identified by Nostr public keys.
- **Mailer**: Service that sends one-time passwords to users via email (or other methods) but never accesses key material.

### Threshold Signatures

Pomade uses FROST (Flexible Round-Optimized Schnorr Threshold) signatures:

- Keys are split into `n` shares
- Only `threshold` shares are needed to sign
- Example: 2-of-3 means any 2 of 3 signers can create a valid signature

### Session Model

Each client session is identified by a unique client public key. Multiple sessions can exist for the same user across different devices/applications.

## Configuration

Before using the Client, configure the available signer public keys:

```typescript
import {context} from "@pomade/core"

// Set the available signer pubkeys (hex format)
context.setSignerPubkeys([
  "signer1_pubkey_hex",
  "signer2_pubkey_hex",
  "signer3_pubkey_hex",
])

// Configure indexer relays (optional - uses default relays if not set)
context.setIndexerRelays([
  "wss://relay1.example.com",
  "wss://relay2.example.com",
])
```

## Registration

Registration creates a new signing session by sharding the user's key and distributing shares to signers.

### Basic Registration

```typescript
import {Client} from "@pomade/core"
import {makeSecret, getPubkey} from "@welshman/util"

// Generate or use existing user key
const userSecret = makeSecret() // or use existing key
const userPubkey = getPubkey(userSecret)

// Register with 2-of-3 threshold
const {ok, clientOptions, messages} = await Client.register(
  2, // threshold - minimum signers needed
  3, // n - total number of signers
  userSecret, // user's private key
  true, // enable recovery (optional, default: true)
)

if (ok) {
  // Create client instance
  const client = new Client(clientOptions)

  console.log("Client pubkey:", client.pubkey)
  console.log("User pubkey:", client.userPubkey)
  console.log("Signers:", client.peers)

  // Store clientOptions securely for later use
  // DO NOT store userSecret - it's only needed during registration
} else {
  console.error("Registration failed:", messages)
}
```

### Restoring a Client from Stored Options

```typescript
// Load clientOptions from storage
const clientOptions = {
  secret: "stored_client_secret",
  group: storedGroupPackage,
  peers: ["peer1_pubkey", "peer2_pubkey", "peer3_pubkey"],
}

const client = new Client(clientOptions)
```

## Signing Events

Sign Nostr events using threshold signatures:

```typescript
import {makeEvent} from "@welshman/util"

// Create an unsigned event
const unsignedEvent = makeEvent(1, {content: "Hello, Nostr!"})

// Sign the event
const {ok, event, messages} = await client.sign(unsignedEvent)

if (ok && event) {
  console.log("Signed event:", event)
  // Publish event to relays
} else {
  console.error("Signing failed:", messages)
}
```

## Encryption (ECDH)

Generate conversation keys for NIP-44 encryption/decryption:

```typescript
import * as nip44 from "nostr-tools/nip44"

// Get conversation key with another user
const recipientPubkey = "recipient_pubkey_hex"
const conversationKey = await client.getConversationKey(recipientPubkey)

if (conversationKey) {
  // Encrypt a message
  const plaintext = "Secret message"
  const ciphertext = nip44.v2.encrypt(plaintext, conversationKey)

  // Decrypt a message
  const decrypted = nip44.v2.decrypt(ciphertext, conversationKey)

  console.log("Decrypted:", decrypted)
}
```

## Recovery Methods

Setting up email recovery allows users to regain access to their keys using only their email address.

**Important Security Notes:**
- Recovery methods MUST be set within 5 minutes of registration, which prevents attackers from hijacking compromised sessions and adding their own recovery method
- The mailer and inbox are permanently bound to the session

### Setting a Recovery Method

```typescript
const inbox = "user@example.com"
const mailerPubkey = "mailer_service_pubkey_hex"
const callbackUrl = "https://myapp.com/recover?challenge="

// Set recovery method
const {ok, messages} = await client.setRecoveryMethod(
  inbox,
  mailerPubkey,
  callbackUrl, // optional - where to send users after email click
)

if (ok) {
  console.log("Recovery method set, waiting for validation email...")

  // User will receive an email with a challenge code
  // Your app should have a way to receive this challenge
  // (either via callback URL or manual user input)
} else {
  console.error("Failed to set recovery method:", messages)
}
```

### Finalizing Recovery Method

After the user receives the validation email:

```typescript
// User provides the challenge from their email
const challenge = "base58_encoded_challenge_from_email"

const {ok, messages} = await client.finalizeRecoveryMethod(challenge)

if (ok) {
  console.log("Email validated! Recovery method is now active.")
} else {
  console.error("Validation failed:", messages)
}
```

## Account Recovery

Recovery allows users to regain access to their keys using only their email.

### Recovery Flow

Use this when users need to recover their actual private key:

```typescript
import {Client, parseChallenge} from "@pomade/core"

async function recoverAccount(email: string): Promise<string | null> {
  // Step 1: Start recovery
  const {ok, clientSecret, messages} = await Client.startRecovery(
    email,
    "https://myapp.com/recover?challenge=", // optional callback URL
  )

  if (!ok) {
    console.error("Failed to start recovery:", messages)
    return null
  }

  console.log(`Recovery email sent to ${email}`)

  // Step 2: Wait for user to receive email and provide challenge
  const challenge = await waitForUserChallenge() // Your UI implementation

  // Step 3: Finalize recovery
  const {ok: finalizeOk, userSecret} = await Client.finalizeRecovery(
    clientSecret,
    challenge,
  )

  if (finalizeOk && userSecret) {
    console.log("Account recovered successfully!")

    // User now has their private key back
    // You can re-register a new session or use the key directly
    return userSecret
  }

  console.error("Recovery failed")
  return null
}
```

### Login Flow (Create New Session)

Use this when users just need to sign in on a new device (more secure than key recovery):

```typescript
async function loginWithEmail(email: string): Promise<Client | null> {
  // Step 1: Start login
  const {ok, clientSecret, messages} = await Client.startLogin(
    email,
    "https://myapp.com/login?challenge=", // optional callback URL
  )

  if (!ok) {
    console.error("Failed to start login:", messages)
    return null
  }

  console.log(`Login email sent to ${email}`)

  // Step 2: Wait for user to receive email and provide challenge
  const challenge = await waitForUserChallenge() // Your UI implementation

  // Step 3: Finalize login
  const {ok: finalizeOk, clientOptions} = await Client.finalizeLogin(
    clientSecret,
    challenge,
  )

  if (finalizeOk && clientOptions) {
    console.log("Logged in successfully!")

    // Create new client with the recovered session
    const client = new Client(clientOptions)

    // Store clientOptions for this device
    await storeClientOptions(clientOptions)

    return client
  }

  console.error("Login failed")
  return null
}
```

### Recovery with Multiple Accounts

If multiple pubkeys are associated with the same email:

```typescript
// Start recovery for specific pubkey
const {ok, clientSecret} = await Client.startRecovery(
  "user@example.com",
  undefined, // no callback URL
  "specific_user_pubkey_hex", // specify which account to recover
)

// If pubkey is not specified, mailer may send multiple challenges
// User can choose which account to recover
```

### Handling Callback URLs

If you provide a callback URL, the mailer will append the challenge:

```
https://myapp.com/recover?challenge=base58_encoded_challenge
```

## Session Management

Manage multiple sessions across devices and applications. Sessions are authentaticated based on the user's key, so it's possible to manage pomade sessions without being logged in via pomade. This is out of scope of this guide, but check the implementation of these methods to see how it works.

### Listing All Sessions

```typescript
// List all sessions for the user's pubkey across all signers
const sessions = await client.listSessions()

// sessions is a Map<clientPubkey, sessionInfo[]>
for (const [clientPubkey, sessionItems] of sessions.entries()) {
  console.log(`Session: ${clientPubkey}`)

  for (const item of sessionItems) {
    console.log(`  Signer: ${item.peer}`)
    console.log(`  Email: ${item.inbox || "not set"}`)
    console.log(`  Created: ${new Date(item.created_at * 1000)}`)
    console.log(`  Last active: ${new Date(item.last_activity * 1000)}`)
  }
}
```

### Deleting Current Session (Logout)

```typescript
// Log out of current device
const {ok, messages} = await client.deleteSession(
  client.pubkey, // this session's client pubkey
  client.peers, // all signers for this session
)

if (ok) {
  console.log("Logged out successfully")
  // Clear local storage
  client.stop()
}
```

### Deleting Other Sessions (Remote Logout)

```typescript
// Get all sessions
const sessions = await client.listSessions()

// Find suspicious or old sessions
for (const [clientPubkey, items] of sessions.entries()) {
  const lastActivity = Math.max(...items.map(i => i.last_activity))
  const daysSinceActivity = (Date.now() / 1000 - lastActivity) / 86400

  if (daysSinceActivity > 30) {
    console.log(`Deleting inactive session: ${clientPubkey}`)

    // Delete the session
    const peers = items.map(i => i.peer)
    await client.deleteSession(clientPubkey, peers)
  }
}
// Delete a session
async function revokeSession(sessionInfo: any) {
  const {ok} = await client.deleteSession(
    sessionInfo.clientPubkey,
    sessionInfo.peers,
  )

  if (ok) {
    console.log("Session revoked")
  }
}
```

---

## Additional Resources

- [Protocol Specification](PROTOCOL.md) - Complete protocol details
- [Core Package README](packages/core/README.md) - API reference
- [Integration Tests](packages/core/__tests__/integration.test.ts) - Working code examples
- [Security Considerations](PROTOCOL.md#threat-model) - Threat model and security analysis
