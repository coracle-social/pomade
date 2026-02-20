// Mirrors ref/frost/src/util/helpers.ts

use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::Error;

/// Generate `size` random bytes.
pub fn random_bytes(size: usize) -> Vec<u8> {
    let mut buf = vec![0u8; size];
    OsRng.fill_bytes(&mut buf);
    buf
}

/// Generate 32 random bytes.
pub fn random_bytes_32() -> [u8; 32] {
    let mut buf = [0u8; 32];
    OsRng.fill_bytes(&mut buf);
    buf
}

/// Find a record by idx in a slice of items that have an `idx` field.
/// Mirrors `get_record` in the TS implementation.
pub fn get_record<T: HasIdx + Clone>(records: &[T], idx: u32) -> Result<T, Error> {
    records
        .iter()
        .find(|r| r.idx() == idx)
        .cloned()
        .ok_or_else(|| Error::RecordNotFound(idx))
}

/// Trait for types that carry a participant index.
pub trait HasIdx {
    fn idx(&self) -> u32;
}

/// Compute a BIP340-style tagged hash prefix: SHA256(tag) || SHA256(tag).
pub fn taghash(tag: &str) -> [u8; 64] {
    let hash: [u8; 32] = Sha256::digest(tag.as_bytes()).into();
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&hash);
    out[32..].copy_from_slice(&hash);
    out
}

/// BIP340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || data...).
pub fn hash340(tag: &str, data: &[&[u8]]) -> [u8; 32] {
    let prefix = taghash(tag);
    let mut hasher = Sha256::new();
    hasher.update(&prefix);
    for d in data {
        hasher.update(d);
    }
    hasher.finalize().into()
}
