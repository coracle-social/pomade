#![allow(dead_code)]

use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

pub const HTTP_AUTH: u32 = 27235;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NostrEvent {
    pub id: String,
    pub pubkey: String,
    pub created_at: u64,
    pub kind: u32,
    pub tags: Vec<Vec<String>>,
    pub content: String,
    pub sig: String,
}

impl NostrEvent {
    /// Compute the canonical event ID (SHA-256 of the serialized event array).
    pub fn compute_id(&self) -> [u8; 32] {
        let arr = serde_json::json!([
            0,
            self.pubkey,
            self.created_at,
            self.kind,
            self.tags,
            self.content,
        ]);
        Sha256::digest(arr.to_string().as_bytes()).into()
    }

    /// Verify the event's ID and Schnorr signature.
    pub fn verify(&self) -> bool {
        let Ok(id_bytes) = hex::decode(&self.id) else {
            return false;
        };
        let Ok(pubkey_bytes) = hex::decode(&self.pubkey) else {
            return false;
        };
        let Ok(sig_bytes) = hex::decode(&self.sig) else {
            return false;
        };

        // Check ID matches content hash
        if id_bytes != self.compute_id().as_slice() {
            return false;
        }

        // Verify BIP340 Schnorr signature
        let Ok(pk_arr): Result<[u8; 32], _> = pubkey_bytes.try_into() else {
            return false;
        };
        let Ok(sig_arr): Result<[u8; 64], _> = sig_bytes.try_into() else {
            return false;
        };
        let Ok(id_arr): Result<[u8; 32], _> = id_bytes.try_into() else {
            return false;
        };

        use k256::schnorr::{Signature, VerifyingKey};
        let Ok(vk) = VerifyingKey::from_bytes(&pk_arr) else {
            return false;
        };
        let Ok(sig) = Signature::try_from(sig_arr.as_slice()) else {
            return false;
        };
        vk.verify_raw(&id_arr, &sig).is_ok()
    }

    pub fn get_tag_value(&self, name: &str) -> Option<&str> {
        self.tags
            .iter()
            .find(|t| t.first().map(|s| s.as_str()) == Some(name))
            .and_then(|t| t.get(1))
            .map(|s| s.as_str())
    }
}

/// Parse and validate a NIP-98 `Authorization: Nostr <base64>` header.
/// Returns the verified event if valid for the given URL path and method.
pub fn parse_auth(header: &str, url: &str, path: &str) -> Option<NostrEvent> {
    let token = header.strip_prefix("Nostr ")?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(token)
        .ok()?;
    let event: NostrEvent = serde_json::from_slice(&decoded).ok()?;

    if !event.verify() {
        return None;
    }
    if event.kind != HTTP_AUTH {
        return None;
    }
    // created_at must be within ±15 seconds of now
    let t = event.created_at;
    if t < now().saturating_sub(15) || t > now() + 5 {
        return None;
    }
    let expected_url = format!("{}{}", url, path);
    if event.get_tag_value("u") != Some(&expected_url) {
        return None;
    }
    if event.get_tag_value("method") != Some("POST") {
        return None;
    }

    Some(event)
}
