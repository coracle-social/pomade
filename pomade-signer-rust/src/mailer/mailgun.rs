use crate::mailer::{Email, MailFuture, Mailer};

pub struct MailgunMailer {
    pub client: reqwest::Client,
    pub api_key: String,
    pub domain: String,
    pub region: MailgunRegion,
}

pub enum MailgunRegion {
    Us,
    Eu,
}

impl MailgunMailer {
    fn api_base(&self) -> &'static str {
        match self.region {
            MailgunRegion::Us => "https://api.mailgun.net/v3",
            MailgunRegion::Eu => "https://api.eu.mailgun.net/v3",
        }
    }
}

impl Mailer for MailgunMailer {
    fn send(&self, from_email: &str, from_name: &str, email: Email) -> MailFuture {
        let client = self.client.clone();
        let url = format!("{}/{}/messages", self.api_base(), self.domain);
        let key = self.api_key.clone();
        let from = format!("{} <{}>", from_name, from_email);
        Box::pin(async move {
            let res = client
                .post(&url)
                .basic_auth("api", Some(&key))
                .form(&[
                    ("from", from.as_str()),
                    ("to", email.to.as_str()),
                    ("subject", email.subject.as_str()),
                    ("text", email.text.as_str()),
                    ("html", email.html.as_str()),
                ])
                .send()
                .await
                .map_err(|e| e.to_string())?;

            if res.status().is_success() {
                Ok(())
            } else {
                Err(format!("mailgun error: {}", res.status()))
            }
        })
    }
}
