#!/usr/bin/env node

import "dotenv/config"
import {call, on} from '@welshman/lib'
import {Socket, SocketEvent, SocketStatus} from '@welshman/net'
import {Nip01Signer} from "@welshman/signer"
import {Signer, context} from "@pomade/core"
import {sqliteStorage} from "./storage.js"
import {createEmailProvider, loadEmailConfigFromEnv} from "./email/index.js"

// Turn on verbose logging
context.debug = true

// Load configuration from environment variables
const secret = process.env.POMADE_SECRET
const relays = process.env.POMADE_RELAYS?.split(",") || []
const dbPath = process.env.POMADE_DB_PATH || "./pomade-signer.db"

// Validate required configuration
if (!secret) {
  console.error("Error: POMADE_SECRET environment variable is required")
  process.exit(1)
}

if (relays.length === 0) {
  console.error("Error: POMADE_RELAYS environment variable is required")
  process.exit(1)
}

// Load email configuration
let emailProvider
try {
  const emailConfig = loadEmailConfigFromEnv()
  emailProvider = createEmailProvider(emailConfig)
  console.log(`Email provider: ${emailConfig.provider}`)
} catch (error) {
  console.error(`Error: ${error instanceof Error ? error.message : String(error)}`)
  process.exit(1)
}

const signer = Nip01Signer.fromSecret(secret)

const storage = sqliteStorage({path: dbPath, signer})

const service = new Signer({
  signer,
  relays,
  storage,
  sendChallenge: async payload => {
    try {
      await emailProvider.sendChallenge(payload.email, payload.otp)
    } catch (error) {
      console.error(`Failed to send challenge email: ${error instanceof Error ? error.message : String(error)}`)
    }
  },
})

signer.getPubkey().then((pubkey: string) => {
  console.log(`Running as: ${pubkey}`)
})

console.log(`Listening on relays: ${relays.join(", ")}`)

// Handle unhandled rejections
process.on("unhandledRejection", (reason, promise) => {
  console.error("Unhandled Rejection at:", promise, "reason:", reason)
  service.stop()
  process.exit(1)
})

// Handle uncaught exceptions
process.on("uncaughtException", (error) => {
  console.error("Uncaught Exception:", error)
  service.stop()
  process.exit(1)
})

// Handle shutdown gracefully
process.on("SIGINT", () => {
  console.log("\nShutting down signer service...")
  service.stop()
  process.exit(0)
})

process.on("SIGTERM", () => {
  console.log("\nShutting down signer service...")
  service.stop()
  process.exit(0)
})
