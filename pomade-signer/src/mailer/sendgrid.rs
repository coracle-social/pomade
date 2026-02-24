use serde_json::json;

use crate::mailer::{Email, MailFuture, Mailer};

pub struct SendgridMailer {
    pub client: reqwest::Client,
    pub api_key: String,
}

impl Mailer for SendgridMailer {
    fn send(&self, from_email: &str, from_name: &str, email: Email) -> MailFuture {
        let client = self.client.clone();
        let key = self.api_key.clone();
        let from_email = from_email.to_string();
        let from_name = from_name.to_string();
        Box::pin(async move {
            let res = client
                .post("https://api.sendgrid.com/v3/mail/send")
                .bearer_auth(&key)
                .json(&json!({
                    "from": {"email": from_email, "name": from_name},
                    "personalizations": [{"to": [{"email": email.to}]}],
                    "subject": email.subject,
                    "content": [
                        {"type": "text/plain", "value": email.text},
                        {"type": "text/html", "value": email.html},
                    ],
                }))
                .send()
                .await
                .map_err(|e| e.to_string())?;

            if res.status().is_success() {
                Ok(())
            } else {
                Err(format!("sendgrid error: {}", res.status()))
            }
        })
    }
}
