#![allow(dead_code)]

use serde::{Deserialize, Deserializer, Serialize};

// Security limits to prevent DoS attacks via unbounded payloads
const MAX_HASHES_PER_REQUEST: usize = 10;
const MAX_HASH_VECTORS: usize = 10;
const MAX_MEMBERS: usize = 5;
const MAX_COMMITS: usize = 5;

fn is_hex(s: &str) -> bool {
    !s.is_empty() && s.len().is_multiple_of(2) && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn deserialize_hex<'de, D: Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    let s = String::deserialize(d)?;
    if !is_hex(&s) {
        return Err(serde::de::Error::custom("expected even-length hex string"));
    }
    Ok(s)
}

fn deserialize_hex32<'de, D: Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    let s = String::deserialize(d)?;
    if s.len() != 64 || !is_hex(&s) {
        return Err(serde::de::Error::custom(
            "expected 32-byte hex string (64 chars)",
        ));
    }
    Ok(s)
}

fn deserialize_hex33<'de, D: Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    let s = String::deserialize(d)?;
    if s.len() != 66 || !is_hex(&s) {
        return Err(serde::de::Error::custom(
            "expected 33-byte hex string (66 chars)",
        ));
    }
    Ok(s)
}

fn deserialize_bounded_vec<'de, D, T>(d: D, max: usize) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    let v = Vec::<T>::deserialize(d)?;
    if v.len() > max {
        return Err(serde::de::Error::custom(format!(
            "array exceeds max length {max}"
        )));
    }
    Ok(v)
}

// ---- Primitive newtypes ----

#[derive(Debug, Clone, Serialize)]
pub struct Hex(pub String);

#[derive(Debug, Clone, Serialize)]
pub struct Hex32(pub String);

#[derive(Debug, Clone, Serialize)]
pub struct Hex33(pub String);

impl<'de> Deserialize<'de> for Hex {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        deserialize_hex(d).map(Hex)
    }
}

impl<'de> Deserialize<'de> for Hex32 {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        deserialize_hex32(d).map(Hex32)
    }
}

impl<'de> Deserialize<'de> for Hex33 {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        deserialize_hex33(d).map(Hex33)
    }
}

// ---- Shared sub-types ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Commit {
    pub idx: u32,
    pub pubkey: Hex33,
    pub hidden_pn: Hex33,
    pub binder_pn: Hex33,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    pub commits: BoundedVec<Commit, MAX_COMMITS>,
    pub group_pk: Hex33,
    pub threshold: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Share {
    pub idx: u32,
    pub binder_sn: Hex32,
    pub hidden_sn: Hex32,
    pub seckey: Hex32,
}

/// A [Hex32, Hex32] tuple used for partial signature entries.
pub type PsigEntry = (Hex32, Hex32);

/// A non-empty vec of Hex32 hashes, max MAX_HASHES_PER_REQUEST entries.
#[derive(Debug, Clone, Serialize)]
pub struct SighashVec(pub Vec<Hex32>);

impl<'de> Deserialize<'de> for SighashVec {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v = deserialize_bounded_vec::<D, Hex32>(d, MAX_HASHES_PER_REQUEST)?;
        if v.is_empty() {
            return Err(serde::de::Error::custom(
                "sighash_vec must have at least one entry",
            ));
        }
        Ok(SighashVec(v))
    }
}

/// A Vec<T> that enforces a compile-time max length at deserialization.
/// The const generic N is the maximum allowed length.
#[derive(Debug, Clone, Serialize)]
pub struct BoundedVec<T, const N: usize>(pub Vec<T>);

impl<'de, T: Deserialize<'de>, const N: usize> Deserialize<'de> for BoundedVec<T, N> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        deserialize_bounded_vec(d, N).map(BoundedVec)
    }
}

// ---- Auth types ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordAuth {
    pub email_hash: String,
    pub password_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtpAuth {
    pub email_hash: String,
    pub otp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Auth {
    Password(PasswordAuth),
    Otp(OtpAuth),
}

impl Auth {
    pub fn email_hash(&self) -> &str {
        match self {
            Auth::Password(a) => &a.email_hash,
            Auth::Otp(a) => &a.email_hash,
        }
    }

    pub fn is_password(&self) -> bool {
        matches!(self, Auth::Password(_))
    }

    pub fn is_otp(&self) -> bool {
        matches!(self, Auth::Otp(_))
    }
}

// ---- Session ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionItem {
    pub pubkey: Hex32,
    pub client: Hex32,
    pub created_at: u64,
    pub last_activity: u64,
    pub threshold: u32,
    pub total: u32,
    pub idx: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
}

// ---- Request / Response types ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub share: Share,
    pub group: Group,
    pub recovery: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterResponse {
    pub ok: bool,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignRequestInner {
    pub content: Option<String>,
    pub hashes: BoundedVec<SighashVec, MAX_HASH_VECTORS>,
    pub members: BoundedVec<u32, MAX_MEMBERS>,
    pub stamp: u64,
    #[serde(rename = "type")]
    pub kind: String,
    pub gid: Hex32,
    pub sid: Hex32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignRequest {
    pub request: SignRequestInner,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignResult {
    pub idx: u32,
    pub psigs: Vec<PsigEntry>,
    pub pubkey: Hex33,
    pub sid: Hex32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignResponse {
    pub ok: bool,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<SignResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcdhRequest {
    pub idx: u32,
    pub members: BoundedVec<u32, MAX_MEMBERS>,
    pub ecdh_pk: Hex32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcdhResult {
    pub idx: u32,
    pub keyshare: Hex,
    pub members: BoundedVec<u32, MAX_MEMBERS>,
    pub ecdh_pk: Hex,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcdhResponse {
    pub ok: bool,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<EcdhResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoverySetupRequest {
    pub email: String,
    pub password_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoverySetupResponse {
    pub ok: bool,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeRequest {
    pub prefix: String,
    pub email_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeResponse {
    pub ok: bool,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginStartRequest {
    pub auth: Auth,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginStartResponse {
    pub ok: bool,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub items: Option<Vec<SessionItem>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginSelectRequest {
    pub client: Hex32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginSelectResponse {
    pub ok: bool,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<Group>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryStartRequest {
    pub auth: Auth,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryStartResponse {
    pub ok: bool,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub items: Option<Vec<SessionItem>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoverySelectRequest {
    pub client: Hex32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoverySelectResponse {
    pub ok: bool,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub share: Option<Share>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<Group>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionListRequest {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionListResponse {
    pub ok: bool,
    pub message: String,
    pub items: Vec<SessionItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionDeleteRequest {
    pub client: Hex32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionDeleteResponse {
    pub ok: bool,
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    #[test]
    fn test_hex_validation() {
        assert!(is_hex("aabbcc"));
        assert!(is_hex("0123456789abcdef"));
        assert!(is_hex("AABBCC")); // Uppercase is valid
        assert!(!is_hex("")); // Empty is invalid
        assert!(!is_hex("aabbc")); // Odd length is invalid
        assert!(!is_hex("gggg")); // Invalid chars
        assert!(!is_hex("aabbcg")); // Contains invalid char
    }

    #[test]
    fn test_hex32_deserialization() {
        let valid = "\"aabbccdd11223344556677889900aabbccdd11223344556677889900aabbccdd\"";
        let result: Result<Hex32, _> = serde_json::from_str(valid);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().0.len(), 64);

        // Too short
        let short = "\"aabbcc\"";
        let result: Result<Hex32, _> = serde_json::from_str(short);
        assert!(result.is_err());

        // Too long
        let long = "\"aabbccdd11223344556677889900aabbccdd11223344556677889900aabbccddee\"";
        let result: Result<Hex32, _> = serde_json::from_str(long);
        assert!(result.is_err());

        // Invalid hex
        let invalid = "\"gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg\"";
        let result: Result<Hex32, _> = serde_json::from_str(invalid);
        assert!(result.is_err());
    }

    #[test]
    fn test_hex33_deserialization() {
        let valid = "\"02aabbccdd11223344556677889900aabbccdd11223344556677889900aabbccdd\"";
        let result: Result<Hex33, _> = serde_json::from_str(valid);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().0.len(), 66);

        // Too short
        let short = "\"02aabbcc\"";
        let result: Result<Hex33, _> = serde_json::from_str(short);
        assert!(result.is_err());
    }

    #[test]
    fn test_bounded_vec_deserialization() {
        // Valid: within bounds
        let valid = "[1, 2, 3]";
        let result: Result<BoundedVec<u32, 5>, _> = serde_json::from_str(valid);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().0.len(), 3);

        // At limit
        let at_limit = "[1, 2, 3, 4, 5]";
        let result: Result<BoundedVec<u32, 5>, _> = serde_json::from_str(at_limit);
        assert!(result.is_ok());

        // Exceeds limit
        let exceeds = "[1, 2, 3, 4, 5, 6]";
        let result: Result<BoundedVec<u32, 5>, _> = serde_json::from_str(exceeds);
        assert!(result.is_err());
    }

    #[test]
    fn test_sighash_vec_deserialization() {
        // Valid: non-empty, within bounds
        let valid = r#"["aabbccdd11223344556677889900aabbccdd11223344556677889900aabbccdd"]"#;
        let result: Result<SighashVec, _> = serde_json::from_str(valid);
        assert!(result.is_ok());

        // Empty is invalid
        let empty = "[]";
        let result: Result<SighashVec, _> = serde_json::from_str(empty);
        assert!(result.is_err());
    }

    #[test]
    fn test_auth_enum() {
        let password_auth = PasswordAuth {
            email_hash: "hash123".to_string(),
            password_hash: "pw_hash".to_string(),
        };
        let auth = Auth::Password(password_auth.clone());
        assert_eq!(auth.email_hash(), "hash123");
        assert!(auth.is_password());
        assert!(!auth.is_otp());

        let otp_auth = OtpAuth {
            email_hash: "hash456".to_string(),
            otp: "123456".to_string(),
        };
        let auth = Auth::Otp(otp_auth);
        assert_eq!(auth.email_hash(), "hash456");
        assert!(!auth.is_password());
        assert!(auth.is_otp());
    }

    #[test]
    fn test_group_serialization() {
        let group = Group {
            commits: BoundedVec(vec![Commit {
                idx: 0,
                pubkey: Hex33("02".to_string() + &"a".repeat(64)),
                hidden_pn: Hex33("02".to_string() + &"b".repeat(64)),
                binder_pn: Hex33("02".to_string() + &"c".repeat(64)),
            }]),
            group_pk: Hex33("02".to_string() + &"d".repeat(64)),
            threshold: 1,
        };

        let json = serde_json::to_string(&group).unwrap();
        let deserialized: Group = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.threshold, 1);
        assert_eq!(deserialized.commits.0.len(), 1);
    }

    #[test]
    fn test_share_serialization() {
        let share = Share {
            idx: 0,
            binder_sn: Hex32("a".repeat(64)),
            hidden_sn: Hex32("b".repeat(64)),
            seckey: Hex32("c".repeat(64)),
        };

        let json = serde_json::to_string(&share).unwrap();
        let deserialized: Share = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.idx, 0);
    }

    #[test]
    fn test_request_response_types() {
        // RegisterRequest
        let register = RegisterRequest {
            share: Share {
                idx: 0,
                binder_sn: Hex32("a".repeat(64)),
                hidden_sn: Hex32("b".repeat(64)),
                seckey: Hex32("c".repeat(64)),
            },
            group: Group {
                commits: BoundedVec(vec![]),
                group_pk: Hex33("02".to_string() + &"d".repeat(64)),
                threshold: 1,
            },
            recovery: true,
        };
        let json = serde_json::to_string(&register).unwrap();
        let _deserialized: RegisterRequest = serde_json::from_str(&json).unwrap();

        // RegisterResponse
        let response = RegisterResponse {
            ok: true,
            message: "Success".to_string(),
        };
        let json = serde_json::to_string(&response).unwrap();
        let deserialized: RegisterResponse = serde_json::from_str(&json).unwrap();
        assert!(deserialized.ok);
    }

    #[test]
    fn test_session_item_serialization() {
        let item = SessionItem {
            pubkey: Hex32("a".repeat(64)),
            client: Hex32("b".repeat(64)),
            created_at: 1234567890,
            last_activity: 1234567891,
            threshold: 2,
            total: 3,
            idx: 1,
            email: Some("test@example.com".to_string()),
        };

        let json = serde_json::to_string(&item).unwrap();
        let deserialized: SessionItem = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.created_at, 1234567890);
        assert_eq!(deserialized.email, Some("test@example.com".to_string()));
    }

    #[test]
    fn test_sign_request_validation() {
        // Valid sign request
        let valid = SignRequest {
            request: SignRequestInner {
                content: Some("test content".to_string()),
                hashes: BoundedVec(vec![SighashVec(vec![Hex32("a".repeat(64))])]),
                members: BoundedVec(vec![0, 1]),
                stamp: 1234567890,
                kind: "sign".to_string(),
                gid: Hex32("b".repeat(64)),
                sid: Hex32("c".repeat(64)),
            },
        };
        let json = serde_json::to_string(&valid).unwrap();
        let _deserialized: SignRequest = serde_json::from_str(&json).unwrap();
    }

    #[test]
    fn test_challenge_request_response() {
        let request = ChallengeRequest {
            prefix: "AB".to_string(),
            email_hash: "hash123".to_string(),
        };
        let json = serde_json::to_string(&request).unwrap();
        let deserialized: ChallengeRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.prefix, "AB");

        let response = ChallengeResponse {
            ok: true,
            message: "Check your email".to_string(),
        };
        let json = serde_json::to_string(&response).unwrap();
        let deserialized: ChallengeResponse = serde_json::from_str(&json).unwrap();
        assert!(deserialized.ok);
    }

    #[test]
    fn test_recovery_setup_request() {
        let request = RecoverySetupRequest {
            email: "user@example.com".to_string(),
            password_hash: "a".repeat(64),
        };
        let json = serde_json::to_string(&request).unwrap();
        let deserialized: RecoverySetupRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.email, "user@example.com");
    }

    #[test]
    fn test_login_flow_types() {
        // LoginStartRequest
        let start = LoginStartRequest {
            auth: Auth::Password(PasswordAuth {
                email_hash: "hash".to_string(),
                password_hash: "pw".to_string(),
            }),
        };
        let json = serde_json::to_string(&start).unwrap();
        let _deserialized: LoginStartRequest = serde_json::from_str(&json).unwrap();

        // LoginStartResponse
        let start_response = LoginStartResponse {
            ok: true,
            message: "Found sessions".to_string(),
            items: Some(vec![]),
        };
        let json = serde_json::to_string(&start_response).unwrap();
        let deserialized: LoginStartResponse = serde_json::from_str(&json).unwrap();
        assert!(deserialized.items.is_some());

        // LoginSelectRequest
        let select = LoginSelectRequest {
            client: Hex32("a".repeat(64)),
        };
        let json = serde_json::to_string(&select).unwrap();
        let deserialized: LoginSelectRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.client.0, "a".repeat(64));
    }

    #[test]
    fn test_recovery_flow_types() {
        // RecoveryStartRequest
        let start = RecoveryStartRequest {
            auth: Auth::Otp(OtpAuth {
                email_hash: "hash".to_string(),
                otp: "123456".to_string(),
            }),
        };
        let json = serde_json::to_string(&start).unwrap();
        let _deserialized: RecoveryStartRequest = serde_json::from_str(&json).unwrap();

        // RecoverySelectRequest
        let select = RecoverySelectRequest {
            client: Hex32("a".repeat(64)),
        };
        let json = serde_json::to_string(&select).unwrap();
        let _deserialized: RecoverySelectRequest = serde_json::from_str(&json).unwrap();

        // RecoverySelectResponse
        let response = RecoverySelectResponse {
            ok: true,
            message: "Success".to_string(),
            share: None,
            group: None,
        };
        let json = serde_json::to_string(&response).unwrap();
        let deserialized: RecoverySelectResponse = serde_json::from_str(&json).unwrap();
        assert!(deserialized.share.is_none());
    }

    #[test]
    fn test_session_list_and_delete() {
        // SessionListResponse
        let list_response = SessionListResponse {
            ok: true,
            message: "Found sessions".to_string(),
            items: vec![],
        };
        let json = serde_json::to_string(&list_response).unwrap();
        let deserialized: SessionListResponse = serde_json::from_str(&json).unwrap();
        assert!(deserialized.items.is_empty());

        // SessionDeleteRequest
        let delete_req = SessionDeleteRequest {
            client: Hex32("a".repeat(64)),
        };
        let json = serde_json::to_string(&delete_req).unwrap();
        let _deserialized: SessionDeleteRequest = serde_json::from_str(&json).unwrap();

        // SessionDeleteResponse
        let delete_res = SessionDeleteResponse {
            ok: true,
            message: "Deleted".to_string(),
        };
        let json = serde_json::to_string(&delete_res).unwrap();
        let deserialized: SessionDeleteResponse = serde_json::from_str(&json).unwrap();
        assert!(deserialized.ok);
    }

    #[test]
    fn test_ecdh_types() {
        // EcdhRequest
        let request = EcdhRequest {
            idx: 0,
            members: BoundedVec(vec![0, 1]),
            ecdh_pk: Hex32("a".repeat(64)),
        };
        let json = serde_json::to_string(&request).unwrap();
        let deserialized: EcdhRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.idx, 0);

        // EcdhResult
        let result = EcdhResult {
            idx: 0,
            keyshare: Hex("02".to_string() + &"b".repeat(64)),
            members: BoundedVec(vec![0, 1]),
            ecdh_pk: Hex("c".repeat(64)),
        };
        let json = serde_json::to_string(&result).unwrap();
        let deserialized: EcdhResult = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.keyshare.0.len(), 66);

        // EcdhResponse
        let response = EcdhResponse {
            ok: true,
            message: "Success".to_string(),
            result: Some(result),
        };
        let json = serde_json::to_string(&response).unwrap();
        let deserialized: EcdhResponse = serde_json::from_str(&json).unwrap();
        assert!(deserialized.result.is_some());
    }
}
