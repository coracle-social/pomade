// Mirrors ref/frost/src/ecc/util.ts

use std::ops::Neg;

use k256::{
    EncodedPoint, ProjectivePoint, Scalar, U256,
    elliptic_curve::{
        ops::Reduce,
        sec1::{FromEncodedPoint, ToEncodedPoint},
    },
};

use crate::Error;

/// Secp256k1 field prime P.
pub const P: U256 =
    U256::from_be_hex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");

/// Secp256k1 group order N.
pub const N: U256 =
    U256::from_be_hex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");

/// Reduce a 256-bit integer mod N into a Scalar.
pub fn mod_n(x: U256) -> Scalar {
    <Scalar as Reduce<U256>>::reduce(x)
}

/// Scalar from raw bytes, reduced mod N.
pub fn scalar_from_bytes(bytes: &[u8; 32]) -> Scalar {
    mod_n(U256::from_be_slice(bytes))
}

/// Scalar to big-endian bytes.
pub fn scalar_to_bytes(s: &Scalar) -> [u8; 32] {
    s.to_bytes().into()
}

/// Add two scalars mod N.
pub fn scalar_add(a: Scalar, b: Scalar) -> Scalar {
    a + b
}

/// Multiply two scalars mod N.
pub fn scalar_mul(a: Scalar, b: Scalar) -> Scalar {
    a * b
}

/// Negate a scalar mod N.
pub fn scalar_neg(a: Scalar) -> Scalar {
    -a
}

/// Modular inverse of a scalar (panics if zero).
pub fn scalar_invert(a: &Scalar) -> Result<Scalar, Error> {
    Option::from(a.invert()).ok_or(Error::ScalarInversion)
}

/// Compute base^exp mod N using repeated squaring.
/// Mirrors `pow_n` in the TS implementation.
pub fn pow_n(base: u64, exp: u64) -> Scalar {
    if exp == 0 {
        return Scalar::ONE;
    }
    let mut result = Scalar::ONE;
    let mut b = mod_n(U256::from(base));
    let mut e = exp;
    while e > 0 {
        if e & 1 == 1 {
            result *= b;
        }
        b *= b;
        e >>= 1;
    }
    result
}

/// Lift an x-only (32-byte) or compressed (33-byte) pubkey to a ProjectivePoint.
/// Mirrors `lift_x` in the TS implementation — always returns the even-Y variant.
pub fn lift_x(bytes: &[u8]) -> Result<ProjectivePoint, Error> {
    let encoded = match bytes.len() {
        32 => {
            // Prepend 0x02 (even parity) to get a compressed point.
            let mut buf = [0u8; 33];
            buf[0] = 0x02;
            buf[1..].copy_from_slice(bytes);
            EncodedPoint::from_bytes(buf).map_err(|_| Error::InvalidPoint)?
        }
        33 => EncodedPoint::from_bytes(bytes).map_err(|_| Error::InvalidPoint)?,
        _ => return Err(Error::InvalidPoint),
    };
    let pt = ProjectivePoint::from_encoded_point(&encoded);
    Option::from(pt).ok_or(Error::InvalidPoint)
}

/// Serialize a ProjectivePoint to a 33-byte compressed encoding.
pub fn serialize_point(pt: &ProjectivePoint) -> [u8; 33] {
    let encoded = pt.to_encoded_point(true);
    let bytes = encoded.as_bytes();
    let mut out = [0u8; 33];
    out.copy_from_slice(bytes);
    out
}

/// Deserialize a 33-byte compressed point.
pub fn deserialize_point(bytes: &[u8; 33]) -> Result<ProjectivePoint, Error> {
    let encoded = EncodedPoint::from_bytes(bytes as &[u8]).map_err(|_| Error::InvalidPoint)?;
    Option::from(ProjectivePoint::from_encoded_point(&encoded)).ok_or(Error::InvalidPoint)
}

/// Returns true if the point has an even Y coordinate.
pub fn has_even_y(pt: &ProjectivePoint) -> bool {
    let encoded = pt.to_encoded_point(true);
    encoded.as_bytes()[0] == 0x02
}

/// Negate a point (flip Y).
pub fn negate_point(pt: &ProjectivePoint) -> ProjectivePoint {
    Neg::neg(*pt)
}
