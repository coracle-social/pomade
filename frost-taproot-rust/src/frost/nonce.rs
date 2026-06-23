/// Nonce generation and derivation for FROST signing sessions.
///
/// Uses HMAC-SHA256 to derive secret nonces from a share secret and a
/// random 32-byte code. Only the code needs to be stored; secrets are
/// re-derived on demand during signing, eliminating the need to persist
/// secret nonce material.
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::helpers::get_pubkey;
use crate::util::helpers::random_bytes_32;

use super::types::{DerivedNonce, MemberNonce, SecretNoncePair};

type HmacSha256 = Hmac<Sha256>;

const DOMAIN_BINDER: &[u8] = b"bifrost/nonce/binder/v1";
const DOMAIN_HIDDEN: &[u8] = b"bifrost/nonce/hidden/v1";

/// Derive a secret nonce component via HMAC-SHA256.
///
/// `key = share_secret`, `msg = code || domain`
fn derive_nonce_secret(share_secret: &[u8; 32], code: &[u8; 32], domain: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(share_secret).expect("HMAC accepts any key size");
    mac.update(code);
    mac.update(domain);
    mac.finalize().into_bytes().into()
}

/// Generate a fresh nonce pair from a share secret.
///
/// A random 32-byte code is generated; the secret nonces are derived from
/// it via HMAC. Only the `DerivedNonce` (containing the code and public
/// points) needs to be stored or transmitted — secrets are re-derived
/// during signing via [`derive_secret_nonce`].
pub fn generate_nonce_pair(share_secret: &[u8; 32]) -> DerivedNonce {
    let code = random_bytes_32();
    let binder_sn = derive_nonce_secret(share_secret, &code, DOMAIN_BINDER);
    let hidden_sn = derive_nonce_secret(share_secret, &code, DOMAIN_HIDDEN);
    let binder_pn = get_pubkey(&binder_sn);
    let hidden_pn = get_pubkey(&hidden_sn);
    DerivedNonce {
        binder_pn,
        hidden_pn,
        code,
    }
}

/// Generate `count` nonce pairs from a share secret.
pub fn generate_nonce_pairs(share_secret: &[u8; 32], count: usize) -> Vec<DerivedNonce> {
    (0..count)
        .map(|_| generate_nonce_pair(share_secret))
        .collect()
}

/// Re-derive the secret nonce pair from a code and share secret.
///
/// Call this during signing when you need the secret values but only
/// stored the code.
pub fn derive_secret_nonce(share_secret: &[u8; 32], code: &[u8; 32]) -> SecretNoncePair {
    let binder_sn = derive_nonce_secret(share_secret, code, DOMAIN_BINDER);
    let hidden_sn = derive_nonce_secret(share_secret, code, DOMAIN_HIDDEN);
    SecretNoncePair {
        code: *code,
        binder_sn,
        hidden_sn,
    }
}

/// Verify that a code produces the expected public nonces.
///
/// Use this to authenticate a code sent back by a peer during signing.
pub fn verify_nonce_code(share_secret: &[u8; 32], nonce: &MemberNonce) -> bool {
    let derived = derive_secret_nonce(share_secret, &nonce.code);
    let binder_pn = get_pubkey(&derived.binder_sn);
    let hidden_pn = get_pubkey(&derived.hidden_sn);
    // Plain equality is fine here: both sides are public nonce points
    // (the re-derived points and the peer-supplied ones), not secrets, so
    // there is no secret-dependent timing to leak.
    binder_pn == nonce.binder_pn && hidden_pn == nonce.hidden_pn
}

/// Attach a member index to a `DerivedNonce`, producing a `MemberNonce`.
pub fn to_member_nonce(nonce: DerivedNonce, idx: u32) -> MemberNonce {
    MemberNonce {
        idx,
        binder_pn: nonce.binder_pn,
        hidden_pn: nonce.hidden_pn,
        code: nonce.code,
    }
}

/// Validate that a `DerivedNonce` contains well-formed curve points.
pub fn validate_nonce(nonce: &DerivedNonce) -> bool {
    use crate::ecc::util::lift_x;
    lift_x(&nonce.binder_pn).is_ok() && lift_x(&nonce.hidden_pn).is_ok()
}
