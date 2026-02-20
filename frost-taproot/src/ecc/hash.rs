// Mirrors ref/frost/src/ecc/hash.ts
// FROST-secp256k1-SHA256-v1 hash functions H1–H5.
// Spec: draft-irtf-cfrg-frost-15, section 6.5.

use k256::{
    elliptic_curve::hash2curve::{ExpandMsg, ExpandMsgXmd, Expander},
    Scalar,
};
use sha2::{Digest, Sha256};

use super::util::mod_n;
use k256::U256;

const DOMAIN: &str = "FROST-secp256k1-SHA256-v1";

/// Build the DST for a given sub-tag.
fn dst(sub: &str) -> Vec<u8> {
    format!("{}{}", DOMAIN, sub).into_bytes()
}

/// hash_to_field using XMD with SHA-256, outputting one field element mod N.
///
/// Mirrors noble's `hash_to_field(msg, 1, { m:1, p:N, k:128, expand:'xmd', hash:sha256, DST })`:
///   1. expand_message_xmd → 48 uniform bytes
///   2. interpret as a big-endian 384-bit integer
///   3. reduce mod N
///
/// The 384-bit → mod-N reduction is done as:
///   value = hi_128_bits * 2^256 + lo_256_bits  (mod N)
fn hash_to_field_n(msg: &[u8], dst_bytes: &[u8]) -> Scalar {
    // Step 1: expand_message_xmd → 48 bytes
    let mut uniform = [0u8; 48];
    ExpandMsgXmd::<Sha256>::expand_message(&[msg], &[dst_bytes], 48)
        .expect("expand_message failed")
        .fill_bytes(&mut uniform);

    // Step 2 & 3: interpret 48 bytes as big-endian integer, reduce mod N.
    // Split into high 16 bytes and low 32 bytes.
    // value = hi * 2^256 + lo  (mod N)
    let (hi16, lo32_slice) = uniform.split_at(16);

    let mut lo32 = [0u8; 32];
    lo32.copy_from_slice(lo32_slice);
    let lo_scalar = mod_n(U256::from_be_slice(&lo32));

    // 2^256 mod N: since 2^256 = N + (2^256 - N), we compute it as a scalar.
    // 2^256 - N = 0x14551231950b75fc4402da1732fc9bebf
    // Represented as 32 bytes (fits in 17 bytes):
    let two256_mod_n = {
        // 2^256 mod N = 2^256 - N (since 2^256 > N)
        // = 0x014551231950b75fc4402da1732fc9bebf (17 bytes)
        // As 32-byte big-endian:
        let bytes =
            hex_literal_32("000000000000000000000000000000014551231950b75fc4402da1732fc9bebf");
        mod_n(U256::from_be_slice(&bytes))
    };

    // hi as a scalar (16 bytes → pad to 32)
    let mut hi32 = [0u8; 32];
    hi32[16..].copy_from_slice(hi16);
    let hi_scalar = mod_n(U256::from_be_slice(&hi32));

    hi_scalar * two256_mod_n + lo_scalar
}

/// Parse a hex literal into a 32-byte array (must be exactly 64 hex chars).
fn hex_literal_32(s: &str) -> [u8; 32] {
    // Pad or truncate to 64 hex chars (32 bytes), right-aligned.
    let padded = format!("{:0>64}", s);
    let b = (0..32)
        .map(|i| u8::from_str_radix(&padded[i * 2..i * 2 + 2], 16).unwrap())
        .collect::<Vec<_>>();
    b.try_into().unwrap()
}

/// H1: rho — binding factor hash.
pub fn h1(msg: &[u8]) -> [u8; 32] {
    let s = hash_to_field_n(msg, &dst("rho"));
    s.to_bytes().into()
}

/// H2: chal — challenge hash.
pub fn h2(msg: &[u8]) -> [u8; 32] {
    let s = hash_to_field_n(msg, &dst("chal"));
    s.to_bytes().into()
}

/// H3: nonce — nonce generation hash.
pub fn h3(msg: &[u8]) -> [u8; 32] {
    let s = hash_to_field_n(msg, &dst("nonce"));
    s.to_bytes().into()
}

/// H4: msg — plain SHA-256 with domain prefix.
pub fn h4(msg: &[u8]) -> [u8; 32] {
    let prefix = dst("msg");
    let mut hasher = Sha256::new();
    hasher.update(&prefix);
    hasher.update(msg);
    hasher.finalize().into()
}

/// H5: com — plain SHA-256 with domain prefix.
pub fn h5(msg: &[u8]) -> [u8; 32] {
    let prefix = dst("com");
    let mut hasher = Sha256::new();
    hasher.update(&prefix);
    hasher.update(msg);
    hasher.finalize().into()
}
