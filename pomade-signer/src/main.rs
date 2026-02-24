#[cfg(feature = "nitro")]
mod attestation;
#[cfg(feature = "nitro")]
mod encrypted_storage;
#[cfg(feature = "nitro")]
mod kms;
mod mailer;
mod message;
mod nostr;
mod pow;
mod ratelimit;
mod schema;
mod session;
mod signer;
mod storage;
#[cfg(feature = "nitro")]
mod vsock;
#[cfg(feature = "nitro")]
mod vsock_connector;

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::post,
};
use clap::Parser;
#[cfg(feature = "nitro")]
use serde::Deserialize;
use serde_json::Value;
use tokio::signal;
use tower_http::cors::{Any, CorsLayer};

#[cfg(feature = "nitro")]
use encrypted_storage::EncryptedBackend;
use mailer::{
    Mailer,
    mailgun::{MailgunMailer, MailgunRegion},
    postmark::PostmarkMailer,
    resend::ResendMailer,
    sendgrid::SendgridMailer,
    sendlayer::SendlayerMailer,
};
use signer::{Signer, SignerOptions};
use storage::SledBackend;

#[derive(Parser)]
#[command(about = "Pomade FROST signer server")]
struct Args {
    /// Publicly reachable URL of this server (e.g. https://signer.example.com)
    #[arg(long, env = "SIGNER_URL")]
    url: String,

    /// Address to listen on
    #[arg(long, env = "LISTEN_ADDR", default_value = "0.0.0.0:3000")]
    listen: String,

    /// VSOCK port to listen on (Nitro Enclave mode; mutually exclusive with --listen)
    #[cfg(feature = "nitro")]
    #[arg(long, env = "VSOCK_PORT", conflicts_with = "listen")]
    vsock_port: Option<u32>,

    /// VSOCK port of the parent's outbound HTTP CONNECT proxy (Nitro Enclave mode)
    #[cfg(feature = "nitro")]
    #[arg(long, env = "OUTBOUND_VSOCK_PORT", default_value = "3001")]
    outbound_vsock_port: u32,

    /// AWS region for KMS calls (Nitro Enclave mode)
    #[cfg(feature = "nitro")]
    #[arg(long, env = "KMS_REGION", default_value = "us-east-1")]
    kms_region: String,

    /// KMS key ARN or alias for the sealing key ciphertext
    #[cfg(feature = "nitro")]
    #[arg(long, env = "KMS_SEALING_KEY_ARN")]
    kms_sealing_key_arn: String,

    /// Base64-encoded KMS ciphertext for the sealing key (produced by `aws kms encrypt`)
    #[cfg(feature = "nitro")]
    #[arg(long, env = "KMS_SEALING_KEY_CIPHERTEXT")]
    kms_sealing_key_ciphertext: String,

    /// KMS-encrypted env vars to provision at startup, as ENV_VAR_NAME=ciphertext_b64 pairs.
    /// May be repeated for multiple secrets, e.g.:
    ///   --kms-secret RESEND_API_KEY=<ciphertext> --kms-secret MAILGUN_API_KEY=<ciphertext>
    /// Each ciphertext is decrypted via KMS attestation and injected into the process
    /// environment, so existing MAIL_PROVIDER env var lookups work without modification.
    #[cfg(feature = "nitro")]
    #[arg(long = "kms-secret", env = "KMS_SECRETS", value_delimiter = ',')]
    kms_secrets: Vec<String>,

    /// Path to the sled database directory
    #[arg(long, env = "DB_PATH", default_value = "./signer-db")]
    db: String,

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

fn build_mailer(provider: &str, client: reqwest::Client) -> Box<dyn Mailer> {
    match provider {
        "postmark" => Box::new(PostmarkMailer {
            client,
            api_token: require_env("POSTMARK_API_TOKEN"),
        }),
        "sendgrid" => Box::new(SendgridMailer {
            client,
            api_key: require_env("SENDGRID_API_KEY"),
        }),
        "mailgun" => Box::new(MailgunMailer {
            client,
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
            client,
            api_key: require_env("SENDLAYER_API_KEY"),
        }),
        "resend" => Box::new(ResendMailer {
            client,
            api_key: require_env("RESEND_API_KEY"),
        }),
        other => panic!("unknown MAIL_PROVIDER: {}", other),
    }
}

fn require_env(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| panic!("{} must be set", key))
}

/// Provision secrets from KMS at startup using Nitro attestation.
///
/// Decrypts the sealing key and injects any additional KMS-encrypted env vars
/// into the process environment so that existing `require_env` calls work
/// without modification. `kms_secrets` is a list of `ENV_VAR_NAME=ciphertext_b64`
/// pairs.
#[cfg(feature = "nitro")]
async fn provision_secrets(
    kms_region: &str,
    kms_sealing_key_arn: &str,
    kms_sealing_key_ciphertext: &str,
    kms_secrets: &[String],
    client: &reqwest::Client,
) -> [u8; 32] {
    let credentials = kms::fetch_credentials(client)
        .await
        .expect("failed to fetch IMDS credentials");

    let sealing_bytes = kms::kms_decrypt(
        client,
        kms_sealing_key_ciphertext,
        Some(kms_sealing_key_arn),
        kms_region,
        &credentials,
    )
    .await
    .expect("failed to decrypt sealing key from KMS");

    let sealing_key: [u8; 32] = sealing_bytes
        .try_into()
        .expect("KMS sealing key plaintext must be exactly 32 bytes");

    for pair in kms_secrets {
        let (name, ciphertext) = pair
            .split_once('=')
            .unwrap_or_else(|| panic!("--kms-secret must be ENV_VAR_NAME=ciphertext, got: {pair}"));

        let bytes = kms::kms_decrypt(client, ciphertext, None, kms_region, &credentials)
            .await
            .unwrap_or_else(|e| panic!("failed to decrypt KMS secret for {name}: {e}"));

        let value = String::from_utf8(bytes)
            .unwrap_or_else(|_| panic!("KMS secret for {name} is not valid UTF-8"));

        // Safety: single-threaded at this point in startup, before the tokio
        // runtime spawns any request-handling tasks.
        unsafe { std::env::set_var(name, value) };
    }

    sealing_key
}

#[tokio::main]
async fn main() {
    env_logger::init();

    let args = Args::parse();

    let sled = SledBackend::open(&args.db).expect("failed to open sled database");

    let test_mode = std::env::var("TEST_MODE").is_ok();

    if !test_mode && args.mail_provider.is_none() {
        panic!("MAIL_PROVIDER must be set when TEST_MODE is not enabled");
    }

    #[cfg(feature = "nitro")]
    let http_client = {
        let bridge_port = vsock_connector::spawn_bridge(args.outbound_vsock_port).await;
        vsock_connector::vsock_client(bridge_port)
    };
    #[cfg(not(feature = "nitro"))]
    let http_client = reqwest::Client::new();

    #[cfg(feature = "nitro")]
    let sealing_key = provision_secrets(
        &args.kms_region,
        &args.kms_sealing_key_arn,
        &args.kms_sealing_key_ciphertext,
        &args.kms_secrets,
        &http_client,
    )
    .await;

    let mailer = args
        .mail_provider
        .as_deref()
        .map(|p| build_mailer(p, http_client.clone()));

    let options = SignerOptions {
        url: args.url,
        register_pow: if test_mode { 0 } else { 20 },
        argon_m: if test_mode { 1024 } else { 64 * 1024 },
        from_email: args.mail_from_email,
        from_name: args.mail_from_name,
        mailer,
        test_mode,
    };

    #[cfg(feature = "nitro")]
    let signer = Arc::new(Signer::open(
        options,
        EncryptedBackend::new(sled, &sealing_key),
    ));
    #[cfg(not(feature = "nitro"))]
    let signer = Arc::new(Signer::open(options, sled));

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    #[cfg(feature = "nitro")]
    let app = Router::new().route("/attest", post(handle_attest));
    #[cfg(not(feature = "nitro"))]
    let app = Router::new();

    let app = app
        .route("/*path", post(handle))
        .with_state(signer)
        .layer(cors);

    #[cfg(feature = "nitro")]
    if let Some(port) = args.vsock_port {
        let listener = vsock::VsockListener::bind(port).expect("failed to bind vsock");
        log::info!("listening on vsock port {port}");
        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown_signal())
            .await
            .expect("server error");
        return;
    }

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

/// Optional fields that a caller may embed in the attestation document.
/// All values are base64-encoded bytes; the NSM will include them verbatim
/// in the signed CBOR document so clients can bind a nonce or public key
/// to the enclave's identity.
#[cfg(feature = "nitro")]
#[derive(Deserialize, Default)]
struct AttestRequest {
    user_data: Option<String>,
    nonce: Option<String>,
    public_key: Option<String>,
}

#[cfg(feature = "nitro")]
async fn handle_attest(body: Option<Json<AttestRequest>>) -> impl IntoResponse {
    use base64::{Engine, engine::general_purpose::STANDARD};

    let req = body.map(|Json(r)| r).unwrap_or_default();

    let decode = |s: Option<String>| -> Result<Option<Vec<u8>>, String> {
        s.map(|b64| {
            STANDARD
                .decode(&b64)
                .map_err(|e| format!("base64 decode error: {e}"))
        })
        .transpose()
    };

    let user_data = match decode(req.user_data) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"ok": false, "message": e})),
            );
        }
    };
    let nonce = match decode(req.nonce) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"ok": false, "message": e})),
            );
        }
    };
    let public_key = match decode(req.public_key) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"ok": false, "message": e})),
            );
        }
    };

    match attestation::get_attestation_doc(user_data, nonce, public_key) {
        Ok(doc) => (
            StatusCode::OK,
            Json(serde_json::json!({"ok": true, "document": STANDARD.encode(&doc)})),
        ),
        Err(e) => {
            log::error!("[attest]: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(
                    serde_json::json!({"ok": false, "message": "Failed to generate attestation document."}),
                ),
            )
        }
    }
}
