#!/usr/bin/env node

import "dotenv/config"
import http from "node:http"
import {Nip01Signer} from "@welshman/signer"
import {Signer, context} from "@pomade/core"
import {sqliteStorage} from "./storage.js"
import {EmailProvider, createEmailProvider, loadEmailConfigFromEnv} from "./email/index.js"

// Turn on verbose logging
context.debug = true

// Apply test mode overrides before anything else
if (process.env.TEST_MODE) {
  context.registerPow = 0
  context.argonOptions = {...context.argonOptions, m: 1024}
}

// Load configuration from environment variables
const secret = process.env.POMADE_SECRET
const url = process.env.POMADE_URL
const port = parseInt(process.env.POMADE_PORT || "3000", 10)
const dbPath = process.env.POMADE_DATABASE || "./pomade-signer.db"

// Validate required configuration
if (!secret) {
  console.error("Error: POMADE_SECRET environment variable is required")
  process.exit(1)
}

if (!url) {
  console.error("Error: POMADE_URL environment variable is required")
  process.exit(1)
}

// Load email configuration
let emailProvider: EmailProvider
if (!process.env.TEST_MODE) {
  try {
    const emailConfig = loadEmailConfigFromEnv()
    emailProvider = createEmailProvider(emailConfig)
    console.log(`Email provider: ${emailConfig.provider}`)
  } catch (error) {
    console.error(`Error: ${error instanceof Error ? error.message : String(error)}`)
    process.exit(1)
  }
}

const signer = Nip01Signer.fromSecret(secret)

const storage = sqliteStorage({path: dbPath, signer})

const service = new Signer({
  url,
  signer,
  storage,
  sendChallenge: async payload => {
    if (process.env.TEST_MODE) {
      console.log(`[challenge] otp=${payload.otp} to=${payload.email}`)
    } else {
      try {
        await emailProvider.sendChallenge(payload.email, payload.otp)
      } catch (error) {
        console.error(`Failed to send challenge email: ${error instanceof Error ? error.message : String(error)}`)
      }
    }
  },
})

const server = http.createServer(async (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*")
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS")
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization")

  if (req.method === "OPTIONS") {
    res.writeHead(204)
    res.end()
    return
  }

  if (req.method !== "POST") {
    res.writeHead(405, {"Content-Type": "application/json"})
    res.end(JSON.stringify({ok: false, message: "Method not allowed"}))
    return
  }

  let body: Record<string, unknown> = {}
  try {
    const chunks: Buffer[] = []
    for await (const chunk of req) chunks.push(chunk as Buffer)
    const raw = Buffer.concat(chunks).toString()
    if (raw) body = JSON.parse(raw)
  } catch {
    res.writeHead(400, {"Content-Type": "application/json"})
    res.end(JSON.stringify({ok: false, message: "Invalid JSON"}))
    return
  }

  const path = new URL(req.url || "/", url).pathname
  const authHeader = req.headers["authorization"] || ""
  const result = await service.handle(path, authHeader, body)

  res.writeHead(200, {"Content-Type": "application/json"})
  res.end(JSON.stringify(result))
})

signer.getPubkey().then((pubkey: string) => {
  console.log(`Running as: ${pubkey}`)
})

server.listen(port, () => {
  console.log(`Listening on port ${port} (${url})`)
})

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
  server.close(() => process.exit(0))
})

process.on("SIGTERM", () => {
  console.log("\nShutting down signer service...")
  service.stop()
  server.close(() => process.exit(0))
})
