#![allow(dead_code)]

use serde::{Deserialize, Deserializer, Serialize};

// Security limits to prevent DoS attacks via unbounded payloads
const MAX_HASHES_PER_REQUEST: usize = 10;
const MAX_HASH_VECTORS: usize = 10;
const MAX_MEMBERS: usize = 5;
const MAX_COMMITS: usize = 5;

fn is_hex(s: &str) -> bool {
    !s.is_empty() && s.len() % 2 == 0 && s.chars().all(|c| c.is_ascii_hexdigit())
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
