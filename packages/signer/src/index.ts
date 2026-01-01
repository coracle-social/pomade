#!/usr/bin/env node

import "dotenv/config"
import bcrypt from 'bcrypt'
import {Signer} from "@pomade/core"
import {sqliteStorageFactory} from "./storage.js"

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

// Create storage factory
const storage = sqliteStorageFactory({path: dbPath})

// Start signer service
const signer = new Signer({
  secret,
  relays,
  storage,
  hash: p => bcrypt.hash(p, 10),
  compare: bcrypt.compare,
  sendChallenge: async payload => {
    console.log(payload)
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
