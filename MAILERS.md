# Email Providers

The Pomade signer supports multiple email providers for sending authentication challenges to users. This document describes the supported providers and their configuration.

## Overview

When a user requests a login challenge, the signer generates a one-time password (OTP) and sends it via email. The challenge expires after 15 minutes. The pluggable email provider system allows you to choose the service that best fits your needs.

## Supported Providers

### Postmark

Postmark is a reliable transactional email service with excellent deliverability.

**Configuration:**
```bash
MAIL_PROVIDER=postmark
MAIL_FROM_EMAIL=noreply@example.com
MAIL_FROM_NAME=Pomade Signer
POSTMARK_API_TOKEN=your_postmark_api_token
```

**Getting started:**
1. Sign up at [postmarkapp.com](https://postmarkapp.com/)
2. Create a server and get your API token
3. Verify your sender signature or domain

### SendGrid

SendGrid is a popular email delivery platform with a generous free tier.

**Configuration:**
```bash
MAIL_PROVIDER=sendgrid
MAIL_FROM_EMAIL=noreply@example.com
MAIL_FROM_NAME=Pomade Signer
SENDGRID_API_KEY=your_sendgrid_api_key
```

**Getting started:**
1. Sign up at [sendgrid.com](https://sendgrid.com/)
2. Create an API key with "Mail Send" permissions
3. Verify your sender identity

### Mailgun

Mailgun is a developer-friendly email service with a pay-as-you-go pricing model.

**Configuration:**
```bash
MAIL_PROVIDER=mailgun
MAIL_FROM_EMAIL=noreply@example.com
MAIL_FROM_NAME=Pomade Signer
MAILGUN_API_KEY=your_mailgun_api_key
MAILGUN_DOMAIN=your_mailgun_domain
MAILGUN_API_REGION=us  # or "eu" for European region
```

**Getting started:**
1. Sign up at [mailgun.com](https://www.mailgun.com/)
2. Add and verify your domain
3. Get your API key from the dashboard
4. Set the correct region (US or EU)

### Sendlayer

Sendlayer is a modern email API with focus on deliverability and developer experience.

**Configuration:**
```bash
MAIL_PROVIDER=sendlayer
MAIL_FROM_EMAIL=noreply@example.com
MAIL_FROM_NAME=Pomade Signer
SENDLAYER_API_KEY=your_sendlayer_api_key
```

**Getting started:**
1. Sign up at [sendlayer.com](https://sendlayer.com/)
2. Create an API key
3. Verify your sender domain

### Resend

Resend is a modern email API built for developers with excellent documentation and DX.

**Configuration:**
```bash
MAIL_PROVIDER=resend
MAIL_FROM_EMAIL=noreply@example.com
MAIL_FROM_NAME=Pomade Signer
RESEND_API_KEY=your_resend_api_key
```

**Getting started:**
1. Sign up at [resend.com](https://resend.com/)
2. Create an API key
3. Verify your domain

## Configuration

All providers require three common environment variables:

- `MAIL_PROVIDER`: The email provider to use (postmark, sendgrid, mailgun, sendlayer, or resend)
- `MAIL_FROM_EMAIL`: The email address that will appear in the "From" field
- `MAIL_FROM_NAME`: The name that will appear in the "From" field (optional, defaults to "Pomade Signer")

Each provider also requires its own specific credentials (API keys, domains, etc.) as shown above.

## Email Template

The challenge email includes:
- A clear subject line: "Your Pomade Login Challenge"
- The challenge code in an easy-to-copy format
- A reminder that the challenge expires in 15 minutes
- A security notice if the user didn't request the challenge
- Both plain text and HTML versions for maximum compatibility

## Troubleshooting

### Email not received

1. Check your spam folder
2. Verify that your sender domain is properly configured with SPF, DKIM, and DMARC records
3. Check your email provider's dashboard for delivery logs and errors
4. Ensure your API keys have the correct permissions

### Authentication errors

1. Verify that the API key is correct and has not expired
2. Check that you're using the correct environment variables for your chosen provider
3. Ensure your sender email/domain is verified with your email provider

### Rate limits

All email providers have rate limits. If you're hitting rate limits:
1. Check your provider's dashboard for current usage
2. Consider upgrading your plan
3. Implement retry logic with exponential backoff (not yet implemented in Pomade)

## Development

For development and testing, you can use any provider's sandbox/test mode:
- SendGrid and Mailgun offer sandbox domains
- Postmark has a test server
- You can also use a temporary email service to test delivery

## Node.js Requirements

The email provider system requires Node.js 18.0.0 or higher, as it uses the built-in `fetch` API for making HTTP requests to email provider APIs.
