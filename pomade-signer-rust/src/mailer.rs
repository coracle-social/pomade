pub mod mailgun;
pub mod postmark;
pub mod resend;
pub mod sendgrid;
pub mod sendlayer;
pub mod smtp;

use std::future::Future;
use std::pin::Pin;

pub struct Email {
    pub to: String,
    pub subject: String,
    pub text: String,
    pub html: String,
}

pub type MailResult = Result<(), String>;
pub type MailFuture = Pin<Box<dyn Future<Output = MailResult> + Send>>;

pub trait Mailer: Send + Sync {
    fn send(&self, from_email: &str, from_name: &str, email: Email) -> MailFuture;
}
