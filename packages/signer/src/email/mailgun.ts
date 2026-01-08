import { BaseEmailProvider } from "./base.js"

export class MailgunProvider extends BaseEmailProvider {
  private apiKey: string
  private domain: string
  private apiRegion: "us" | "eu"

  constructor(config: {
    apiKey: string
    domain: string
    fromEmail: string
    fromName?: string
    apiRegion?: "us" | "eu"
  }) {
    super({ fromEmail: config.fromEmail, fromName: config.fromName })
    this.apiKey = config.apiKey
    this.domain = config.domain
    this.apiRegion = config.apiRegion || "us"
  }

  async sendChallenge(email: string, challenge: string): Promise<void> {
    const { subject, text, html } = this.buildChallengeEmail(challenge)

    const baseUrl =
      this.apiRegion === "eu"
        ? "https://api.eu.mailgun.net"
        : "https://api.mailgun.net"

    const formData = new URLSearchParams()
    formData.append("from", `${this.fromName} <${this.fromEmail}>`)
    formData.append("to", email)
    formData.append("subject", subject)
    formData.append("text", text)
    formData.append("html", html)

    const response = await fetch(
      `${baseUrl}/v3/${this.domain}/messages`,
      {
        method: "POST",
        headers: {
          "Authorization": `Basic ${btoa(`api:${this.apiKey}`)}`,
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: formData.toString(),
      }
    )

    if (!response.ok) {
      const error = await response.text()
      throw new Error(`Mailgun API error: ${response.status} - ${error}`)
    }
  }
}
