mod mailer;
mod message;
mod nostr;
mod pow;
mod ratelimit;
mod schema;
mod session;
mod signer;
mod storage;

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::post,
    Json, Router,
};
use clap::Parser;
use serde_json::Value;
use tokio::signal;
use tower_http::cors::{Any, CorsLayer};

use mailer::{
    mailgun::{MailgunMailer, MailgunRegion},
    postmark::PostmarkMailer,
    resend::ResendMailer,
    sendgrid::SendgridMailer,
    sendlayer::SendlayerMailer,
    Mailer,
};
use signer::{Signer, SignerOptions};
use storage::Storage;

#[derive(Parser)]
#[command(about = "Pomade FROST signer server")]
struct Args {
    /// Publicly reachable URL of this server (e.g. https://signer.example.com)
    #[arg(long, env = "SIGNER_URL")]
    url: String,

    /// Address to listen on
    #[arg(long, env = "LISTEN_ADDR", default_value = "0.0.0.0:3000")]
    listen: String,

    /// Path to the sled database directory
    #[arg(long, env = "DB_PATH", default_value = "./signer-db")]
    db: String,

    /// Minimum proof-of-work difficulty required for registration (NIP-13)
    #[arg(long, env = "REGISTER_POW", default_value_t = 20)]
    register_pow: u32,

    /// Email provider (postmark, sendgrid, mailgun, sendlayer, resend)
    #[arg(long, env = "MAIL_PROVIDER")]
    mail_provider: Option<String>,

    /// Sender email address
    #[arg(long, env = "MAIL_FROM_EMAIL", default_value = "noreply@example.com")]
    mail_from_email: String,

    /// Sender display name
    #[arg(long, env = "MAIL_FROM_NAME", default_value = "Pomade Signer")]
    mail_from_name: String,
}

fn build_mailer(provider: &str) -> Box<dyn Mailer> {
    match provider {
        "postmark" => Box::new(PostmarkMailer {
            api_token: require_env("POSTMARK_API_TOKEN"),
        }),
        "sendgrid" => Box::new(SendgridMailer {
            api_key: require_env("SENDGRID_API_KEY"),
        }),
        "mailgun" => Box::new(MailgunMailer {
            api_key: require_env("MAILGUN_API_KEY"),
            domain: require_env("MAILGUN_DOMAIN"),
            region: match std::env::var("MAILGUN_API_REGION")
                .unwrap_or_default()
                .as_str()
            {
                "eu" => MailgunRegion::Eu,
                _ => MailgunRegion::Us,
            },
        }),
        "sendlayer" => Box::new(SendlayerMailer {
            api_key: require_env("SENDLAYER_API_KEY"),
        }),
        "resend" => Box::new(ResendMailer {
            api_key: require_env("RESEND_API_KEY"),
        }),
        other => panic!("unknown MAIL_PROVIDER: {}", other),
    }
}

fn require_env(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| panic!("{} must be set", key))
}

#[tokio::main]
async fn main() {
    env_logger::init();

    let args = Args::parse();

    let storage = Storage::open(&args.db).expect("failed to open sled database");

    let mailer = args.mail_provider.as_deref().map(build_mailer);

    let options = SignerOptions {
        url: args.url,
        register_pow: args.register_pow,
        from_email: args.mail_from_email,
        from_name: args.mail_from_name,
        mailer,
    };

    let signer = Arc::new(Signer::open(options, &storage).expect("failed to open signer"));

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/*path", post(handle))
        .with_state(signer)
        .layer(cors);

    let listener = tokio::net::TcpListener::bind(&args.listen)
        .await
        .expect("failed to bind");

    log::info!("listening on {}", args.listen);

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .expect("server error");
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    log::info!("signal received, starting graceful shutdown");
}

async fn handle(
    State(signer): State<Arc<Signer>>,
    Path(path): Path<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let result = signer.handle(&format!("/{path}"), auth, &body);

    (StatusCode::OK, Json(result))
}
