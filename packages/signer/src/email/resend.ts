import { BaseEmailProvider } from "./base"

export class ResendProvider extends BaseEmailProvider {
  private apiKey: string

  constructor(config: {
    apiKey: string
    fromEmail: string
    fromName?: string
  }) {
    super({ fromEmail: config.fromEmail, fromName: config.fromName })
    this.apiKey = config.apiKey
  }

  async sendChallenge(email: string, challenge: string): Promise<void> {
    const { subject, text, html } = this.buildChallengeEmail(challenge)

    const response = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${this.apiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        from: `${this.fromName} <${this.fromEmail}>`,
        to: [email],
        subject: subject,
        text: text,
        html: html,
      }),
    })

    if (!response.ok) {
      const error = await response.text()
      throw new Error(`Resend API error: ${response.status} - ${error}`)
    }
  }
}
