import { BaseEmailProvider } from "./base.js"

export class SendGridProvider extends BaseEmailProvider {
  private apiKey: string

  constructor(config: {
    apiKey: string
    fromEmail: string
    fromName?: string
  }) {
    super({ fromEmail: config.fromEmail, fromName: config.fromName })
    this.apiKey = config.apiKey
  }

  async sendChallenge(email: string, otp: string): Promise<void> {
    const { subject, text, html } = this.buildChallengeEmail(otp)

    const response = await fetch("https://api.sendgrid.com/v3/mail/send", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${this.apiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        personalizations: [
          {
            to: [{ email }],
          },
        ],
        from: {
          email: this.fromEmail,
          name: this.fromName,
        },
        subject: subject,
        content: [
          {
            type: "text/plain",
            value: text,
          },
          {
            type: "text/html",
            value: html,
          },
        ],
      }),
      signal: AbortSignal.timeout(30_000),
    })

    if (!response.ok) {
      const error = await response.text()
      throw new Error(`SendGrid API error: ${response.status} - ${error}`)
    }
  }
}
