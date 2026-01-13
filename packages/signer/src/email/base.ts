import { readFileSync } from "fs"
import { join, dirname } from "path"
import { fileURLToPath } from "url"
import Mustache from "mustache"

const __filename = fileURLToPath(import.meta.url)
const __dirname = dirname(__filename)

// Load the compiled HTML template once at module initialization
const templatePath = join(__dirname, "..", "templates", "challenge.html")
let htmlTemplate: string

try {
  htmlTemplate = readFileSync(templatePath, "utf-8")
} catch (error) {
  console.error(`Failed to load email template from ${templatePath}:`, error)
  throw new Error("Email template not found. Run 'npm run build:templates' to compile MJML templates.")
}

export interface EmailProvider {
  sendChallenge(email: string, challenge: string): Promise<void>
}

export abstract class BaseEmailProvider implements EmailProvider {
  protected fromEmail: string
  protected fromName: string

  constructor(config: { fromEmail: string; fromName?: string }) {
    this.fromEmail = config.fromEmail
    this.fromName = config.fromName || "Nostr Signer"
  }

  abstract sendChallenge(email: string, challenge: string): Promise<void>

  protected buildChallengeEmail(challenge: string): {
    subject: string
    text: string
    html: string
  } {
    const subject = "Your Challenge"
    const text = `Someone attempted to log in using your email address. If this was you, please continue by copying the challenge below:\n\n${challenge}\n\nThis challenge will expire in 15 minutes.\n\nIf you did not request this challenge, please ignore this email.\n\n---\n\nThis is an automated message from a Nostr signer. Please do not reply to this email.`
    const html = Mustache.render(htmlTemplate, { challenge })

    return { subject, text, html }
  }
}
