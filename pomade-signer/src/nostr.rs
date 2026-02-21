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
    // created_at must be within ±60 seconds of now
    let t = event.created_at;
    if t < now().saturating_sub(60) || t > now() + 5 {
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

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    fn create_test_event(pubkey: &str, url: &str, method: &str) -> NostrEvent {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        NostrEvent {
            id: "a".repeat(64),
            pubkey: pubkey.to_string(),
            created_at: now,
            kind: HTTP_AUTH,
            tags: vec![
                vec!["u".to_string(), url.to_string()],
                vec!["method".to_string(), method.to_string()],
            ],
            content: "".to_string(),
            sig: "b".repeat(128),
        }
    }

    #[test]
    fn test_nostr_event_compute_id() {
        let event = NostrEvent {
            id: "a".repeat(64),
            pubkey: "b".repeat(64),
            created_at: 1234567890,
            kind: HTTP_AUTH,
            tags: vec![vec!["u".to_string(), "http://test.com".to_string()]],
            content: "test content".to_string(),
            sig: "c".repeat(128),
        };

        let id = event.compute_id();
        assert_eq!(id.len(), 32);

        // Same event should produce same ID
        let id2 = event.compute_id();
        assert_eq!(id, id2);
    }

    #[test]
    fn test_nostr_event_get_tag_value() {
        let event = create_test_event("pubkey", "http://test.com/path", "POST");

        assert_eq!(event.get_tag_value("u"), Some("http://test.com/path"));
        assert_eq!(event.get_tag_value("method"), Some("POST"));
        assert_eq!(event.get_tag_value("nonexistent"), None);
    }

    #[test]
    fn test_parse_auth_invalid_prefix() {
        // Missing "Nostr " prefix
        let result = parse_auth("invalid_token", "http://test.com", "/path");
        assert!(result.is_none());

        // Wrong prefix
        let result = parse_auth("Bearer token", "http://test.com", "/path");
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_auth_invalid_base64() {
        let result = parse_auth("Nostr not_valid_base64!!!", "http://test.com", "/path");
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_auth_invalid_json() {
        let invalid_json = base64::engine::general_purpose::STANDARD.encode("not json");
        let result = parse_auth(
            &format!("Nostr {}", invalid_json),
            "http://test.com",
            "/path",
        );
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_auth_wrong_kind() {
        let mut event = create_test_event(&"b".repeat(64), "http://test.com/path", "POST");
        event.kind = 1; // Wrong kind

        let json = serde_json::to_string(&event).unwrap();
        let encoded = base64::engine::general_purpose::STANDARD.encode(&json);
        let result = parse_auth(&format!("Nostr {}", encoded), "http://test.com", "/path");
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_auth_old_timestamp() {
        let mut event = create_test_event(&"b".repeat(64), "http://test.com/path", "POST");
        event.created_at = 0; // Very old timestamp

        let json = serde_json::to_string(&event).unwrap();
        let encoded = base64::engine::general_purpose::STANDARD.encode(&json);
        let result = parse_auth(&format!("Nostr {}", encoded), "http://test.com", "/path");
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_auth_future_timestamp() {
        let mut event = create_test_event(&"b".repeat(64), "http://test.com/path", "POST");
        event.created_at = now() + 100; // Future timestamp

        let json = serde_json::to_string(&event).unwrap();
        let encoded = base64::engine::general_purpose::STANDARD.encode(&json);
        let result = parse_auth(&format!("Nostr {}", encoded), "http://test.com", "/path");
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_auth_wrong_url() {
        let event = create_test_event(&"b".repeat(64), "http://wrong.com/path", "POST");

        let json = serde_json::to_string(&event).unwrap();
        let encoded = base64::engine::general_purpose::STANDARD.encode(&json);
        let result = parse_auth(&format!("Nostr {}", encoded), "http://test.com", "/path");
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_auth_wrong_method() {
        let event = create_test_event(&"b".repeat(64), "http://test.com/path", "GET");

        let json = serde_json::to_string(&event).unwrap();
        let encoded = base64::engine::general_purpose::STANDARD.encode(&json);
        let result = parse_auth(&format!("Nostr {}", encoded), "http://test.com", "/path");
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_auth_missing_tags() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let event = NostrEvent {
            id: "a".repeat(64),
            pubkey: "b".repeat(64),
            created_at: now,
            kind: HTTP_AUTH,
            tags: vec![], // Missing required tags
            content: "".to_string(),
            sig: "c".repeat(128),
        };

        let json = serde_json::to_string(&event).unwrap();
        let encoded = base64::engine::general_purpose::STANDARD.encode(&json);
        let result = parse_auth(&format!("Nostr {}", encoded), "http://test.com", "/path");
        assert!(result.is_none());
    }

    #[test]
    fn test_now() {
        let t1 = now();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let t2 = now();
        assert!(t2 >= t1);
        assert!(t1 > 1_700_000_000); // Should be after 2023
    }

    #[test]
    fn test_http_auth_constant() {
        assert_eq!(HTTP_AUTH, 27235);
    }
}
