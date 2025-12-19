import type {
  MailerProvider,
  ValidationPayload,
  RecoveryPayload,
} from "@pomade/core"
import {ServerClient} from "postmark"

export class ConsoleMailerProvider implements MailerProvider {
  async sendValidation(payload: ValidationPayload): Promise<void> {
    console.log("=== VALIDATION EMAIL ===")
    console.log("To:", payload.inbox)
    console.log("Challenge:", payload.challenge)
    console.log("Callback URL:", payload.callback_url || "none")
    console.log("========================")
  }

  async sendRecovery(payload: RecoveryPayload): Promise<void> {
    console.log("=== RECOVERY EMAIL ===")
    console.log("To:", payload.inbox)
    console.log("Pubkey:", payload.pubkey)
    console.log("Challenge:", payload.challenge)
    console.log("Callback URL:", payload.callback_url || "none")
    console.log("======================")
  }
}

export class PostmarkMailerProvider implements MailerProvider {
  private client: ServerClient

  constructor(
    private serverToken: string,
    private fromEmail: string,
  ) {
    this.client = new ServerClient(serverToken)
  }

  async sendValidation(payload: ValidationPayload): Promise<void> {
    const callbackInfo = payload.callback_url
      ? `\n\nCallback URL: ${payload.callback_url}`
      : ""

    await this.client.sendEmail({
      From: this.fromEmail,
      To: payload.inbox,
      Subject: "Email Validation",
      TextBody: `Your validation challenge: ${payload.challenge}${callbackInfo}`,
      HtmlBody: `
        <h2>Email Validation</h2>
        <p>Your validation challenge:</p>
        <p><strong>${payload.challenge}</strong></p>
        ${payload.callback_url ? `<p>Callback URL: ${payload.callback_url}</p>` : ""}
      `,
    })
  }

  async sendRecovery(payload: RecoveryPayload): Promise<void> {
    const callbackInfo = payload.callback_url
      ? `\n\nCallback URL: ${payload.callback_url}`
      : ""

    await this.client.sendEmail({
      From: this.fromEmail,
      To: payload.inbox,
      Subject: "Account Recovery",
      TextBody: `Account recovery for pubkey: ${payload.pubkey}\n\nYour recovery challenge: ${payload.challenge}${callbackInfo}`,
      HtmlBody: `
        <h2>Account Recovery</h2>
        <p>Account recovery for pubkey:</p>
        <p><code>${payload.pubkey}</code></p>
        <p>Your recovery challenge:</p>
        <p><strong>${payload.challenge}</strong></p>
        ${payload.callback_url ? `<p>Callback URL: ${payload.callback_url}</p>` : ""}
      `,
    })
  }
}
