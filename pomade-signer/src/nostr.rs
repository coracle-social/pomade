use base64::Engine;
use nostr::nips::nip98::{verify_auth_header, HttpMethod};
use nostr::types::time::Timestamp;
use nostr::util::JsonUtil;
use nostr::{Event, PublicKey, Url};

pub struct NostrAuth {
    pub pubkey: String,
    pub event: Event,
}

pub fn parse_auth(header: &str, base_url: &str, path: &str) -> Option<NostrAuth> {
    let url_str = format!("{}{}", base_url, path);
    let url = Url::parse(&url_str).ok()?;
    let now = Timestamp::now();
    let pubkey: PublicKey = verify_auth_header(header, &url, HttpMethod::POST, now, None).ok()?;

    // Re-extract the event so callers can read fields from it (e.g. id for PoW)
    let token = header.strip_prefix("Nostr ")?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(token)
        .ok()?;
    let event = Event::from_json(&decoded).ok()?;

    Some(NostrAuth {
        pubkey: pubkey.to_hex(),
        event,
    })
}
