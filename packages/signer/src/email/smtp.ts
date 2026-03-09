import nodemailer from "nodemailer"
import { BaseEmailProvider } from "./base.js"

export class SmtpProvider extends BaseEmailProvider {
  private transporter: nodemailer.Transporter

  constructor(config: {
    host: string
    port: number
    secure?: boolean
    user?: string
    password?: string
    fromEmail: string
    fromName?: string
  }) {
    super({ fromEmail: config.fromEmail, fromName: config.fromName })
    this.transporter = nodemailer.createTransport({
      host: config.host,
      port: config.port,
      secure: config.secure ?? config.port === 465,
      auth: config.user ? { user: config.user, pass: config.password } : undefined,
    })
  }

  async sendChallenge(email: string, otp: string): Promise<void> {
    const { subject, text, html } = this.buildChallengeEmail(otp)

    await this.transporter.sendMail({
      from: `${this.fromName} <${this.fromEmail}>`,
      to: email,
      subject,
      text,
      html,
    })
  }
}
