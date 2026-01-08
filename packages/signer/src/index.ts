#!/usr/bin/env node

import "dotenv/config"
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

// Create storage
const storage = sqliteStorage({path: dbPath})

// Start signer service
const signer = new Signer({
  secret,
  relays,
  storage,
  sendChallenge: async payload => {
    try {
      await emailProvider.sendChallenge(payload.email, payload.challenge)
      console.log(`Challenge email sent to ${payload.email}`)
    } catch (error) {
      console.error(`Failed to send challenge email: ${error instanceof Error ? error.message : String(error)}`)
      throw error
    }
  },
})

console.log(`Running as: ${signer.pubkey}`)
console.log(`Listening on relays: ${relays.join(", ")}`)

// Handle unhandled rejections
process.on("unhandledRejection", (reason, promise) => {
  console.error("Unhandled Rejection at:", promise, "reason:", reason)
  signer.stop()
  process.exit(1)
})

// Handle uncaught exceptions
process.on("uncaughtException", (error) => {
  console.error("Uncaught Exception:", error)
  signer.stop()
  process.exit(1)
})

// Handle shutdown gracefully
process.on("SIGINT", () => {
  console.log("\nShutting down signer service...")
  signer.stop()
  process.exit(0)
})

process.on("SIGTERM", () => {
  console.log("\nShutting down signer service...")
  signer.stop()
  process.exit(0)
})
