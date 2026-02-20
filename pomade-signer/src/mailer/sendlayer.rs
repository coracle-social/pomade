use serde_json::json;

use crate::mailer::{Email, MailFuture, Mailer};

pub struct SendlayerMailer {
    pub api_key: String,
}

impl Mailer for SendlayerMailer {
    fn send(&self, from_email: &str, from_name: &str, email: Email) -> MailFuture {
        let key = self.api_key.clone();
        let from_email = from_email.to_string();
        let from_name = from_name.to_string();
        Box::pin(async move {
            let res = reqwest::Client::new()
                .post("https://console.sendlayer.com/api/v1/email")
                .bearer_auth(&key)
                .json(&json!({
                    "From": {"name": from_name, "email": from_email},
                    "To": [{"name": "", "email": email.to}],
                    "Subject": email.subject,
                    "ContentType": "HTML",
                    "HTMLContent": email.html,
                    "PlainContent": email.text,
                }))
                .send()
                .await
                .map_err(|e| e.to_string())?;

            if res.status().is_success() {
                Ok(())
            } else {
                Err(format!("sendlayer error: {}", res.status()))
            }
        })
    }
}
