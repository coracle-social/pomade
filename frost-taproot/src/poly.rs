// Mirrors ref/frost/src/lib/poly.ts
// Polynomial evaluation and Lagrange interpolation over the secp256k1 scalar field.

use k256::Scalar;

use crate::ecc::util::{scalar_from_bytes, scalar_invert};
use crate::util::assert;
use crate::Error;

/// Evaluate a polynomial at x using Horner's method.
/// Coefficients are in ascending order: coeffs[0] + coeffs[1]*x + coeffs[2]*x^2 + ...
/// Mirrors `evaluate_x` in the TS implementation.
pub fn evaluate_x(coeffs: &[Scalar], x: Scalar) -> Result<Scalar, Error> {
    if x == Scalar::ZERO {
        return Err(Error::Assertion("x is zero".to_string()));
    }

    let mut value = Scalar::ZERO;
    for coeff in coeffs.iter().rev() {
        value = value * x + coeff;
    }
    Ok(value)
}

/// Interpolate a polynomial at x=0 (the root) using Lagrange interpolation.
/// Points are (x, y) pairs of Scalars.
/// Mirrors `interpolate_root` in the TS implementation.
pub fn interpolate_root(points: &[(Scalar, Scalar)]) -> Result<Scalar, Error> {
    let xs: Vec<Scalar> = points.iter().map(|(x, _)| *x).collect();
    let mut p = Scalar::ZERO;
    for (x, y) in points {
        let delta = interpolate_x(&xs, *x)?;
        p = p + delta * y;
    }
    Ok(p)
}

/// Compute the Lagrange basis polynomial value at x=0 for the given x-coordinate,
/// relative to the set of x-coordinates L.
/// Mirrors `interpolate_x` in the TS implementation.
pub fn interpolate_x(l: &[Scalar], x: Scalar) -> Result<Scalar, Error> {
    assert::is_included(l, &x)?;
    assert::is_unique_set(l)?;

    let mut numerator = Scalar::ONE;
    let mut denominator = Scalar::ONE;

    for &x_j in l {
        if x_j == x {
            continue;
        }
        numerator = numerator * x_j;
        denominator = denominator * (x_j + (-x)); // x_j - x
    }

    let inv = scalar_invert(&denominator)?;
    Ok(numerator * inv)
}

/// Compute the Lagrange coefficient for participant P relative to members L,
/// evaluated at point x.
/// Mirrors `calc_lagrange_coeff` in the TS implementation.
pub fn calc_lagrange_coeff(l: &[Scalar], p: Scalar, x: Scalar) -> Result<Scalar, Error> {
    assert::is_unique_set(l)?;

    let mut numerator = Scalar::ONE;
    let mut denominator = Scalar::ONE;

    for &x_j in l {
        if x_j == p {
            continue;
        }
        numerator = numerator * (x + (-x_j)); // x - x_j
        denominator = denominator * (p + (-x_j)); // p - x_j
    }

    let inv = scalar_invert(&denominator)?;
    Ok(numerator * inv)
}

/// Convert a u32 participant index to a Scalar.
pub fn index_to_scalar(idx: u32) -> Scalar {
    scalar_from_bytes(&{
        let mut b = [0u8; 32];
        b[28..].copy_from_slice(&idx.to_be_bytes());
        b
    })
}
