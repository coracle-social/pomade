import { BaseEmailProvider } from "./base"

export class SendlayerProvider extends BaseEmailProvider {
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

    const response = await fetch("https://console.sendlayer.com/api/v1/email", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${this.apiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        From: {
          Email: this.fromEmail,
          Name: this.fromName,
        },
        To: [
          {
            Email: email,
          },
        ],
        Subject: subject,
        TextBody: text,
        HtmlBody: html,
      }),
    })

    if (!response.ok) {
      const error = await response.text()
      throw new Error(`Sendlayer API error: ${response.status} - ${error}`)
    }
  }
}
