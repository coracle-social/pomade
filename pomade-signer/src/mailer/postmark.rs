use serde_json::json;

use crate::mailer::{Email, MailFuture, Mailer};

pub struct PostmarkMailer {
    pub api_token: String,
}

impl Mailer for PostmarkMailer {
    fn send(&self, from_email: &str, from_name: &str, email: Email) -> MailFuture {
        let token = self.api_token.clone();
        let from = format!("{} <{}>", from_name, from_email);
        Box::pin(async move {
            let res = reqwest::Client::new()
                .post("https://api.postmarkapp.com/email")
                .header("X-Postmark-Server-Token", &token)
                .json(&json!({
                    "From": from,
                    "To": email.to,
                    "Subject": email.subject,
                    "TextBody": email.text,
                    "HtmlBody": email.html,
                }))
                .send()
                .await
                .map_err(|e| e.to_string())?;

            if res.status().is_success() {
                Ok(())
            } else {
                Err(format!("postmark error: {}", res.status()))
            }
        })
    }
}
