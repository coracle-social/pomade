// Mirrors ref/frost/src/lib/helpers.ts

use k256::Scalar;

use crate::ecc::group::{element_add, scalar_base_multi, serialize_element};
use crate::ecc::hash::h3;
use crate::ecc::util::{lift_x, mod_n, scalar_from_bytes, scalar_to_bytes};
use crate::util::assert;
use crate::util::helpers::{hash340, random_bytes_32};
use crate::Error;
use k256::U256;

/// Generate a secret key by hashing optional auxiliary bytes through H3.
/// Mirrors `generate_seckey` in the TS implementation.
pub fn generate_seckey(aux: Option<&[u8; 32]>) -> [u8; 32] {
    let aux_bytes = match aux {
        Some(a) => *a,
        None => random_bytes_32(),
    };
    h3(&aux_bytes)
}

/// Generate a secret nonce by hashing (aux || secret) through H3.
/// Mirrors `generate_nonce` in the TS implementation.
pub fn generate_nonce(secret: &[u8; 32], aux_seed: Option<&[u8; 32]>) -> [u8; 32] {
    let aux = match aux_seed {
        Some(a) => *a,
        None => random_bytes_32(),
    };
    let mut input = [0u8; 64];
    input[..32].copy_from_slice(&aux);
    input[32..].copy_from_slice(secret);
    h3(&input)
}

/// Derive a compressed public key from a secret key.
/// Mirrors `get_pubkey` in the TS implementation.
pub fn get_pubkey(secret: &[u8; 32]) -> [u8; 33] {
    let scalar = scalar_from_bytes(secret);
    let point = scalar_base_multi(&scalar);
    serialize_element(&point)
}

/// Tweak a secret key by adding a tweak scalar: (seckey + tweak) mod N.
/// Mirrors `tweak_seckey` in the TS implementation.
pub fn tweak_seckey(seckey: &[u8; 32], tweak: &[u8; 32]) -> [u8; 32] {
    let tweak_scalar = scalar_from_bytes(tweak);
    let secret = scalar_from_bytes(seckey);
    scalar_to_bytes(&(secret + tweak_scalar))
}

/// Tweak a public key by adding tweak*G: pubkey_point + tweak*G.
/// Mirrors `tweak_pubkey` in the TS implementation.
pub fn tweak_pubkey(pubkey: &[u8], tweak: &[u8; 32]) -> Result<[u8; 33], Error> {
    let tweak_scalar = scalar_from_bytes(tweak);
    let point = lift_x(pubkey)?;
    let tweak_point = scalar_base_multi(&tweak_scalar);
    let tweaked = element_add(Some(point), Some(tweak_point))?;
    Ok(serialize_element(&tweaked))
}

/// Compute a BIP340-compatible challenge hash.
/// challenge = SHA256(SHA256("BIP0340/challenge") || SHA256("BIP0340/challenge") || R_x || P_x || msg)
/// Mirrors `get_challenge` in the TS implementation.
pub fn get_challenge(pnonce: &[u8], pubkey: &[u8], message: &[u8]) -> Result<Scalar, Error> {
    let grp_pn = convert_pubkey_to_bip340(pnonce)?;
    let grp_pk = convert_pubkey_to_bip340(pubkey)?;
    assert::ok(
        grp_pn.len() == 32,
        "pnonce must be 32 bytes after conversion",
    )?;
    assert::ok(
        grp_pk.len() == 32,
        "pubkey must be 32 bytes after conversion",
    )?;
    let digest = hash340("BIP0340/challenge", &[&grp_pn, &grp_pk, message]);
    Ok(mod_n(U256::from_be_slice(&digest)))
}

/// Convert a pubkey to BIP340 format (x-only, 32 bytes).
/// If 33 bytes (compressed), strip the prefix byte.
/// If 32 bytes, return as-is.
pub fn convert_pubkey_to_bip340(pubkey: &[u8]) -> Result<Vec<u8>, Error> {
    match pubkey.len() {
        33 => Ok(pubkey[1..].to_vec()),
        32 => Ok(pubkey.to_vec()),
        _ => Err(Error::InvalidPoint),
    }
}

/// Convert a pubkey to ECDSA format (compressed, 33 bytes).
/// If 32 bytes (x-only), prepend 0x02.
/// If 33 bytes, return as-is.
pub fn convert_pubkey_to_ecdsa(pubkey: &[u8]) -> Result<Vec<u8>, Error> {
    match pubkey.len() {
        32 => {
            let mut out = vec![0x02u8];
            out.extend_from_slice(pubkey);
            Ok(out)
        }
        33 => Ok(pubkey.to_vec()),
        _ => Err(Error::InvalidPoint),
    }
}
