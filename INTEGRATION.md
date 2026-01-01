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

1. **Running Signer Services**: At least 2-3 signer services running and accessible via Nostr relays. These **must** be run by multiple independent parties who are not likely to collude to steal user keys. Signers handle email delivery directly.
2. **Nostr Relay Access**: Configured relays that both your client and signers can access
3. **User's Nostr Key**: A nostr private key (either existing or newly generated)

## Core Concepts

### Components

- **Client**: Your application that requests signatures on behalf of users. Each session uses a temporary session-specific key.
- **Signer**: Headless services that store key shares and collaborate to create threshold signatures. Identified by Nostr public keys. Signers also handle sending OTP codes via email for recovery flows.

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

Setting up email-based recovery allows users to regain access to their keys using their email address and password (or OTP).

**Important Security Notes:**
- Recovery methods MUST be set within 15 minutes of registration, which prevents attackers from hijacking compromised sessions and adding their own recovery method
- The email is permanently bound to the session

### Setting a Recovery Method

```typescript
const email = "user@example.com"
const password = "user_chosen_password"

// Set recovery method with email and password
const {ok, messages} = await client.setupRecovery(email, password)

if (ok) {
  console.log("Recovery method set successfully!")
  // No email validation required - user can immediately use email/password to recover
} else {
  console.error("Failed to set recovery method:", messages)
}
```

**Note**: The password is hashed using argon2id before being sent to signers, so the plaintext password never leaves the client.

## Account Recovery

Recovery allows users to regain access to their accounts using their email and password, or via OTP if they've forgotten their password.

### Login Flow (Create New Session with Password)

Use this when users need to sign in on a new device using their email and password:

```typescript
async function loginWithPassword(
  email: string,
  password: string,
): Promise<Client | null> {
  // Step 1: Start login with email and password
  const result = await Client.loginWithPassword(email, password)

  if (!result.ok) {
    console.error("Failed to start login:", result.messages)
    return null
  }

  // Step 2: Select which session to log into (if multiple exist)
  const options = result.options
  if (!options || options.length === 0) {
    console.error("No sessions found")
    return null
  }

  // Let user choose or automatically pick the first one
  // Each option is a tuple of [client: string, peers: string[]]
  const [client, peers] = options[0]

  // Step 3: Complete login for selected session
  const {ok, clientOptions} = await Client.selectLogin(
    result.clientSecret,
    client,
    peers,
  )

  if (ok && clientOptions) {
    console.log("Logged in successfully!")

    // Create new client with the new session
    const newClient = new Client(clientOptions)

    // Store clientOptions for this device
    await storeClientOptions(clientOptions)

    return newClient
  }

  console.error("Login failed")
  return null
}
```

### Login Flow with OTP (Forgot Password)

Use this when users have forgotten their password and need to use one-time passwords sent to their email:

```typescript
async function loginWithOTP(email: string): Promise<Client | null> {
  // Step 1: Request OTPs from all signers
  await Client.requestChallenge(email)

  console.log(`OTP codes sent to ${email}`)

  // Step 2: Wait for user to receive emails and provide OTPs
  // Each signer sends a separate email with format: base58(signer_pubkey || otp)
  const challenges = await waitForUserChallenges() // Your UI implementation - collect multiple challenges

  // Step 3: Start login with challenges
  const result = await Client.loginWithChallenge(email, challenges)

  if (!result.ok) {
    console.error("Failed to start login:", result.messages)
    return null
  }

  // Step 4: Select session and complete login (same as password flow)
  // Each option is a tuple of [client: string, peers: string[]]
  const [client, peers] = result.options[0]
  const {ok, clientOptions} = await Client.selectLogin(
    result.clientSecret,
    client,
    peers,
  )

  if (ok && clientOptions) {
    const newClient = new Client(clientOptions)
    await storeClientOptions(clientOptions)
    return newClient
  }

  return null
}
```

### Recovery Flow (Recover Private Key with Password)

Use this when users need to recover their actual private key (less secure than login):

```typescript
async function recoverPrivateKey(
  email: string,
  password: string,
): Promise<string | null> {
  // Step 1: Start recovery with email and password
  const result = await Client.recoverWithPassword(email, password)

  if (!result.ok) {
    console.error("Failed to start recovery:", result.messages)
    return null
  }

  // Step 2: Select which account to recover
  // Each option is a tuple of [client: string, peers: string[]]
  const [client, peers] = result.options[0]

  // Step 3: Complete recovery for selected session
  const {ok, userSecret} = await Client.selectRecovery(
    result.clientSecret,
    client,
    peers,
  )

  if (ok && userSecret) {
    console.log("Account recovered successfully!")
    // User now has their private key back
    return userSecret
  }

  console.error("Recovery failed")
  return null
}
```

### Recovery Flow with OTP

Similar to login with OTP, but returns the private key instead of creating a new session:

```typescript
async function recoverWithOTP(email: string): Promise<string | null> {
  // Request OTPs
  await Client.requestChallenge(email)

  // Collect challenges from user's email
  const challenges = await waitForUserChallenges()

  // Start recovery with challenges
  const result = await Client.recoverWithChallenge(email, challenges)

  if (!result.ok) {
    console.error("Failed to start recovery:", result.messages)
    return null
  }

  // Select session and complete recovery
  // Each option is a tuple of [client: string, peers: string[]]
  const [client, peers] = result.options[0]
  const {ok, userSecret} = await Client.selectRecovery(
    result.clientSecret,
    client,
    peers,
  )

  if (ok && userSecret) {
    return userSecret
  }

  return null
}
```

**Security Note**: Login (creating a new session) is more secure than recovering the private key, as it doesn't expose the user's key material. Use login when possible.

## Session Management

Manage multiple sessions across devices and applications. Sessions are authentaticated based on the user's key, so it's possible to manage pomade sessions without being logged in via pomade. This is out of scope of this guide, but check the implementation of these methods to see how it works.

### Listing All Sessions

```typescript
// List all sessions for the user's pubkey across all signers
const {ok, messages} = await client.listSessions()

if (!ok) {
  console.error("Failed to list sessions")
  return
}

// Each message contains items from a signer
for (const message of messages) {
  if (message?.payload.items) {
    for (const item of message.payload.items) {
      console.log(`Session: ${item.client}`)
      console.log(`  User pubkey: ${item.pubkey}`)
      console.log(`  Signer: ${message.event.pubkey}`)
      console.log(`  Email: ${item.email || "not set"}`)
      console.log(`  Threshold: ${item.threshold}/${item.total}`)
      console.log(`  Index: ${item.idx}`)
      console.log(`  Created: ${new Date(item.created_at * 1000)}`)
      console.log(`  Last active: ${new Date(item.last_activity * 1000)}`)
    }
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
const {ok, messages} = await client.listSessions()

if (!ok) {
  console.error("Failed to list sessions")
  return
}

// Group sessions by client pubkey
const sessionsByClient = new Map<string, {items: any[], peers: string[]}>()

for (const message of messages) {
  if (message?.payload.items) {
    for (const item of message.payload.items) {
      if (!sessionsByClient.has(item.client)) {
        sessionsByClient.set(item.client, {items: [], peers: []})
      }
      const session = sessionsByClient.get(item.client)!
      session.items.push(item)
      session.peers.push(message.event.pubkey)
    }
  }
}

// Find suspicious or old sessions
for (const [clientPubkey, session] of sessionsByClient.entries()) {
  const lastActivity = Math.max(...session.items.map(i => i.last_activity))
  const daysSinceActivity = (Date.now() / 1000 - lastActivity) / 86400

  if (daysSinceActivity > 30) {
    console.log(`Deleting inactive session: ${clientPubkey}`)
    await client.deleteSession(clientPubkey, session.peers)
  }
}
```

---

## Additional Resources

- [Protocol Specification](PROTOCOL.md) - Complete protocol details
- [Core Package README](packages/core/README.md) - API reference
- [Integration Tests](packages/core/__tests__/integration.test.ts) - Working code examples
- [Security Considerations](PROTOCOL.md#threat-model) - Threat model and security analysis
