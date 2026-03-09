use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    message::{MultiPart, SinglePart, header::ContentType},
    transport::smtp::authentication::Credentials,
};

use crate::mailer::{Email, MailFuture, Mailer};

pub struct SmtpMailer {
    pub host: String,
    pub port: u16,
    pub user: Option<String>,
    pub password: Option<String>,
}

impl Mailer for SmtpMailer {
    fn send(&self, from_email: &str, from_name: &str, email: Email) -> MailFuture {
        let from = format!("{} <{}>", from_name, from_email);
        let host = self.host.clone();
        let port = self.port;
        let credentials = self
            .user
            .as_ref()
            .map(|u| Credentials::new(u.clone(), self.password.clone().unwrap_or_default()));

        Box::pin(async move {
            let message = Message::builder()
                .from(
                    from.parse()
                        .map_err(|e| format!("invalid from address: {e}"))?,
                )
                .to(email
                    .to
                    .parse()
                    .map_err(|e| format!("invalid to address: {e}"))?)
                .subject(&email.subject)
                .multipart(
                    MultiPart::alternative()
                        .singlepart(
                            SinglePart::builder()
                                .header(ContentType::TEXT_PLAIN)
                                .body(email.text),
                        )
                        .singlepart(
                            SinglePart::builder()
                                .header(ContentType::TEXT_HTML)
                                .body(email.html),
                        ),
                )
                .map_err(|e| format!("failed to build message: {e}"))?;

            let mut builder = AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&host)
                .map_err(|e| format!("smtp relay error: {e}"))?
                .port(port);

            if let Some(creds) = credentials {
                builder = builder.credentials(creds);
            }

            builder
                .build()
                .send(message)
                .await
                .map(|_| ())
                .map_err(|e| format!("smtp send error: {e}"))
        })
    }
}
