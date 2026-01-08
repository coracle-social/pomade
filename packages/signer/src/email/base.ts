export interface EmailProvider {
  sendChallenge(email: string, challenge: string): Promise<void>
}

export abstract class BaseEmailProvider implements EmailProvider {
  protected fromEmail: string
  protected fromName: string

  constructor(config: { fromEmail: string; fromName?: string }) {
    this.fromEmail = config.fromEmail
    this.fromName = config.fromName || "Pomade Signer"
  }

  abstract sendChallenge(email: string, challenge: string): Promise<void>

  protected buildChallengeEmail(challenge: string): {
    subject: string
    text: string
    html: string
  } {
    const subject = "Your Pomade Login Challenge"
    const text = `Your login challenge is:\n\n${challenge}\n\nThis challenge will expire in 15 minutes.\n\nIf you did not request this challenge, please ignore this email.`
    const html = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Your Pomade Login Challenge</title>
</head>
<body style="margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; background-color: #f5f5f5;">
  <table role="presentation" style="width: 100%; border-collapse: collapse;">
    <tr>
      <td align="center" style="padding: 40px 0;">
        <table role="presentation" style="width: 600px; max-width: 100%; border-collapse: collapse; background-color: #ffffff; border-radius: 8px; box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);">
          <tr>
            <td style="padding: 40px 40px 20px 40px;">
              <h1 style="margin: 0 0 20px 0; font-size: 24px; font-weight: 600; color: #1a1a1a;">Your Login Challenge</h1>
              <p style="margin: 0 0 20px 0; font-size: 16px; line-height: 1.5; color: #4a4a4a;">
                Your Pomade login challenge is:
              </p>
              <div style="background-color: #f8f9fa; border-radius: 6px; padding: 20px; margin: 0 0 20px 0; word-break: break-all;">
                <code style="font-family: 'Courier New', Courier, monospace; font-size: 14px; color: #1a1a1a;">${challenge}</code>
              </div>
              <p style="margin: 0 0 10px 0; font-size: 14px; line-height: 1.5; color: #6a6a6a;">
                This challenge will expire in <strong>15 minutes</strong>.
              </p>
              <p style="margin: 0; font-size: 14px; line-height: 1.5; color: #6a6a6a;">
                If you did not request this challenge, please ignore this email.
              </p>
            </td>
          </tr>
          <tr>
            <td style="padding: 20px 40px 40px 40px; border-top: 1px solid #e5e5e5;">
              <p style="margin: 0; font-size: 12px; line-height: 1.5; color: #9a9a9a;">
                This is an automated message from Pomade Signer. Please do not reply to this email.
              </p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>
    `.trim()

    return { subject, text, html }
  }
}
