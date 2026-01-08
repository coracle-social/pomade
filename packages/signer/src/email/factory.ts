import { EmailProvider } from "./base.js"
import { PostmarkProvider } from "./postmark.js"
import { SendGridProvider } from "./sendgrid.js"
import { MailgunProvider } from "./mailgun.js"
import { SendlayerProvider } from "./sendlayer.js"
import { ResendProvider } from "./resend.js"

export type MailProvider = "postmark" | "sendgrid" | "mailgun" | "sendlayer" | "resend"

export interface EmailConfig {
  provider: MailProvider
  fromEmail: string
  fromName?: string
  postmark?: {
    apiToken: string
  }
  sendgrid?: {
    apiKey: string
  }
  mailgun?: {
    apiKey: string
    domain: string
    apiRegion?: "us" | "eu"
  }
  sendlayer?: {
    apiKey: string
  }
  resend?: {
    apiKey: string
  }
}

export function createEmailProvider(config: EmailConfig): EmailProvider {
  const { provider, fromEmail, fromName } = config

  switch (provider) {
    case "postmark":
      if (!config.postmark?.apiToken) {
        throw new Error("POSTMARK_API_TOKEN is required when using postmark provider")
      }
      return new PostmarkProvider({
        apiToken: config.postmark.apiToken,
        fromEmail,
        fromName,
      })

    case "sendgrid":
      if (!config.sendgrid?.apiKey) {
        throw new Error("SENDGRID_API_KEY is required when using sendgrid provider")
      }
      return new SendGridProvider({
        apiKey: config.sendgrid.apiKey,
        fromEmail,
        fromName,
      })

    case "mailgun":
      if (!config.mailgun?.apiKey || !config.mailgun?.domain) {
        throw new Error("MAILGUN_API_KEY and MAILGUN_DOMAIN are required when using mailgun provider")
      }
      return new MailgunProvider({
        apiKey: config.mailgun.apiKey,
        domain: config.mailgun.domain,
        apiRegion: config.mailgun.apiRegion,
        fromEmail,
        fromName,
      })

    case "sendlayer":
      if (!config.sendlayer?.apiKey) {
        throw new Error("SENDLAYER_API_KEY is required when using sendlayer provider")
      }
      return new SendlayerProvider({
        apiKey: config.sendlayer.apiKey,
        fromEmail,
        fromName,
      })

    case "resend":
      if (!config.resend?.apiKey) {
        throw new Error("RESEND_API_KEY is required when using resend provider")
      }
      return new ResendProvider({
        apiKey: config.resend.apiKey,
        fromEmail,
        fromName,
      })

    default:
      throw new Error(`Unknown mail provider: ${provider}`)
  }
}

export function loadEmailConfigFromEnv(): EmailConfig {
  const provider = process.env.MAIL_PROVIDER as MailProvider | undefined

  if (!provider) {
    throw new Error("MAIL_PROVIDER environment variable is required")
  }

  const validProviders: MailProvider[] = ["postmark", "sendgrid", "mailgun", "sendlayer", "resend"]
  if (!validProviders.includes(provider)) {
    throw new Error(`MAIL_PROVIDER must be one of: ${validProviders.join(", ")}`)
  }

  const fromEmail = process.env.MAIL_FROM_EMAIL
  if (!fromEmail) {
    throw new Error("MAIL_FROM_EMAIL environment variable is required")
  }

  const fromName = process.env.MAIL_FROM_NAME

  const config: EmailConfig = {
    provider,
    fromEmail,
    fromName,
  }

  switch (provider) {
    case "postmark":
      config.postmark = {
        apiToken: process.env.POSTMARK_API_TOKEN || "",
      }
      break

    case "sendgrid":
      config.sendgrid = {
        apiKey: process.env.SENDGRID_API_KEY || "",
      }
      break

    case "mailgun":
      config.mailgun = {
        apiKey: process.env.MAILGUN_API_KEY || "",
        domain: process.env.MAILGUN_DOMAIN || "",
        apiRegion: (process.env.MAILGUN_API_REGION as "us" | "eu") || "us",
      }
      break

    case "sendlayer":
      config.sendlayer = {
        apiKey: process.env.SENDLAYER_API_KEY || "",
      }
      break

    case "resend":
      config.resend = {
        apiKey: process.env.RESEND_API_KEY || "",
      }
      break
  }

  return config
}
