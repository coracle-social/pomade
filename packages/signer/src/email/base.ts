import Mustache from "mustache"
import { loadChallengeTemplateHtml } from "@pomade/templates"

const htmlTemplate = loadChallengeTemplateHtml()

export interface EmailProvider {
  sendChallenge(email: string, otp: string): Promise<void>
}

export abstract class BaseEmailProvider implements EmailProvider {
  protected fromEmail: string
  protected fromName: string

  constructor(config: { fromEmail: string; fromName?: string }) {
    this.fromEmail = config.fromEmail
    this.fromName = config.fromName || "Nostr Signer"
  }

  abstract sendChallenge(email: string, otp: string): Promise<void>

  protected buildChallengeEmail(otp: string): {
    subject: string
    text: string
    html: string
  } {
    const subject = "Your One-Time Password"
    const text = `Someone attempted to log in using your email address. If this was you, please continue by copying the one-time password below:\n\n${otp}\n\nThis code will expire in 15 minutes.\n\nIf you did not request this code, please ignore this email.\n\n---\n\nThis is an automated message from a Nostr signer. Please do not reply to this email.`
    const html = Mustache.render(htmlTemplate, { otp })

    return { subject, text, html }
  }
}
