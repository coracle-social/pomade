#!/usr/bin/env node

import "dotenv/config"
import {call, on} from '@welshman/lib'
import {defaultSocketPolicies, Socket, SocketEvent, SocketStatus} from '@welshman/net'
import {Signer, context} from "@pomade/core"
import {sqliteStorage} from "./storage.js"

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

defaultSocketPolicies.push((socket: Socket) => {
  const unsubscribers = [
    on(socket, SocketEvent.Status, (status: SocketStatus, url: string) => {
      console.log(`${url} ${status}`)
    }),
  ]

  const interval = setInterval(() => {
    if (socket.status === SocketStatus.Open) {
      socket._ws?.send('["PING"]')
    }
  }, 30_000)

  return () => {
    unsubscribers.forEach(call)
    clearInterval(interval)
  }
})

// Create storage
const storage = sqliteStorage({path: dbPath})

// Start signer service
const signer = new Signer({
  secret,
  relays,
  storage,
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
