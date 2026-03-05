use serde_json::json;

use crate::mailer::{Email, MailFuture, Mailer};

pub struct ResendMailer {
    pub client: reqwest::Client,
    pub api_key: String,
}

impl Mailer for ResendMailer {
    fn send(&self, from_email: &str, from_name: &str, email: Email) -> MailFuture {
        let client = self.client.clone();
        let key = self.api_key.clone();
        let from = format!("{} <{}>", from_name, from_email);
        Box::pin(async move {
            let res = client
                .post("https://api.resend.com/emails")
                .bearer_auth(&key)
                .json(&json!({
                    "from": from,
                    "to": [email.to],
                    "subject": email.subject,
                    "text": email.text,
                    "html": email.html,
                }))
                .send()
                .await
                .map_err(|e| e.to_string())?;

            if res.status().is_success() {
                Ok(())
            } else {
                Err(format!("resend error: {}", res.status()))
            }
        })
    }
}
