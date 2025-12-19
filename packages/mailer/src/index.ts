#!/usr/bin/env node

import "dotenv/config"
import {Mailer} from "@pomade/core"
import {sqliteStorageFactory} from "@pomade/sqlite"
import {ConsoleMailerProvider, PostmarkMailerProvider} from "./provider.js"

// Load configuration from environment variables
const secret = process.env.POMADE_SECRET
const relays = process.env.POMADE_RELAYS?.split(",") || []
const dbPath = process.env.POMADE_DB_PATH || "./pomade-mailer.db"
const postmarkServerToken = process.env.POMADE_POSTMARK_SERVER_TOKEN
const postmarkFromEmail = process.env.POMADE_POSTMARK_FROM_EMAIL
const providerType = process.env.POMADE_PROVIDER || "console"

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

// Create provider
let provider
if (providerType === "postmark") {
  if (!postmarkServerToken) {
    console.error("Error: POMADE_POSTMARK_SERVER_TOKEN is required when using postmark provider")
    process.exit(1)
  }
  if (!postmarkFromEmail) {
    console.error("Error: POMADE_POSTMARK_FROM_EMAIL is required when using postmark provider")
    process.exit(1)
  }
  provider = new PostmarkMailerProvider(postmarkServerToken, postmarkFromEmail)
} else {
  provider = new ConsoleMailerProvider()
}

// Start mailer service
const mailer = new Mailer({
  secret,
  relays,
  storage,
  provider,
})

console.log("Pomade Mailer Service started")
console.log("Relays:", relays.join(", "))
console.log("Provider:", providerType)
console.log("Database:", dbPath)

// Handle shutdown gracefully
process.on("SIGINT", () => {
  console.log("\nShutting down mailer service...")
  mailer.stop()
  process.exit(0)
})

process.on("SIGTERM", () => {
  console.log("\nShutting down mailer service...")
  mailer.stop()
  process.exit(0)
})
