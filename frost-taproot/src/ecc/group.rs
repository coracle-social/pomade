// Mirrors ref/frost/src/ecc/group.ts
// Group operations on secp256k1 using k256.

use k256::{ProjectivePoint, Scalar};
use rand::RngCore;
use rand::rngs::OsRng;

use super::util::{deserialize_point, mod_n, scalar_from_bytes, scalar_to_bytes, serialize_point};
use crate::Error;
use k256::U256;

/// The group order N.
pub fn order() -> Scalar {
    // N as a scalar is zero (it wraps), so we expose the U256 constant from util.
    // Callers needing N for negation use `Scalar::ZERO - Scalar::ONE` + 1 = N-1 pattern,
    // or use scalar_neg directly.
    Scalar::ZERO
}

/// The identity (point at infinity).
pub fn identity() -> ProjectivePoint {
    ProjectivePoint::IDENTITY
}

/// Generate a random scalar in [1, N-1].
pub fn random_scalar() -> Scalar {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    mod_n(U256::from_be_slice(&bytes))
}

/// Add two points. Either may be the identity (None-equivalent in TS was null).
pub fn element_add(
    a: Option<ProjectivePoint>,
    b: Option<ProjectivePoint>,
) -> Result<ProjectivePoint, Error> {
    match (a, b) {
        (None, None) => Err(Error::BothPointsNull),
        (None, Some(b)) => Ok(b),
        (Some(a), None) => Ok(a),
        (Some(a), Some(b)) => Ok(a + b),
    }
}

/// Sum a slice of optional points.
pub fn element_add_many(elems: &[Option<ProjectivePoint>]) -> Result<ProjectivePoint, Error> {
    if elems.is_empty() {
        return Err(Error::BothPointsNull);
    }
    let mut acc = elems[0];
    for &e in &elems[1..] {
        acc = Some(element_add(acc, e)?);
    }
    acc.ok_or(Error::BothPointsNull)
}

/// Scalar multiplication: k * A.
pub fn scalar_multi(a: &ProjectivePoint, k: &Scalar) -> ProjectivePoint {
    a * k
}

/// Scalar base multiplication: k * G.
pub fn scalar_base_multi(k: &Scalar) -> ProjectivePoint {
    ProjectivePoint::GENERATOR * k
}

/// Serialize a point to 33 compressed bytes.
pub fn serialize_element(pt: &ProjectivePoint) -> [u8; 33] {
    serialize_point(pt)
}

/// Deserialize a point from 33 compressed bytes.
pub fn deserialize_element(bytes: &[u8; 33]) -> Result<ProjectivePoint, Error> {
    deserialize_point(bytes)
}

/// Serialize a scalar index (u32) as a 32-byte big-endian value.
/// Mirrors `G.SerializeScalar(idx)` where idx is a small integer.
pub fn serialize_scalar_u32(idx: u32) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[28..].copy_from_slice(&idx.to_be_bytes());
    out
}

/// Serialize a Scalar to 32 bytes.
pub fn serialize_scalar(s: &Scalar) -> [u8; 32] {
    scalar_to_bytes(s)
}

/// Deserialize 32 bytes into a Scalar (reduced mod N).
pub fn deserialize_scalar(bytes: &[u8; 32]) -> Scalar {
    scalar_from_bytes(bytes)
}

pub use super::util::{has_even_y, lift_x, negate_point, pow_n};
