import { BaseEmailProvider } from "./base"

export class PostmarkProvider extends BaseEmailProvider {
  private apiToken: string

  constructor(config: {
    apiToken: string
    fromEmail: string
    fromName?: string
  }) {
    super({ fromEmail: config.fromEmail, fromName: config.fromName })
    this.apiToken = config.apiToken
  }

  async sendChallenge(email: string, challenge: string): Promise<void> {
    const { subject, text, html } = this.buildChallengeEmail(challenge)

    const response = await fetch("https://api.postmarkapp.com/email", {
      method: "POST",
      headers: {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "X-Postmark-Server-Token": this.apiToken,
      },
      body: JSON.stringify({
        From: `${this.fromName} <${this.fromEmail}>`,
        To: email,
        Subject: subject,
        TextBody: text,
        HtmlBody: html,
      }),
    })

    if (!response.ok) {
      const error = await response.text()
      throw new Error(`Postmark API error: ${response.status} - ${error}`)
    }
  }
}
