// Mirrors ref/frost/src/lib/vss.ts
// Verifiable Secret Sharing: coefficient generation and commitments.

use k256::Scalar;

use crate::ecc::group::{scalar_base_multi, serialize_element};
use crate::ecc::util::mod_n;
use crate::util::assert;
use crate::util::helpers::random_bytes_32;
use crate::Error;
use k256::U256;

/// Create polynomial coefficients for a Shamir secret sharing scheme.
/// If fewer secrets are provided than `threshold`, the remaining coefficients are random.
/// Mirrors `create_share_coeffs` in the TS implementation.
pub fn create_share_coeffs(secrets: &[[u8; 32]], threshold: usize) -> Vec<Scalar> {
    let mut coeffs = Vec::with_capacity(threshold);
    for i in 0..threshold {
        let coeff = if let Some(s) = secrets.get(i) {
            mod_n(U256::from_be_slice(s))
        } else {
            mod_n(U256::from_be_slice(&random_bytes_32()))
        };
        coeffs.push(coeff);
    }
    coeffs
}

/// Compute VSS commitments: one compressed public key per coefficient.
/// Mirrors `get_share_commits` in the TS implementation.
pub fn get_share_commits(coeffs: &[Scalar]) -> Vec<[u8; 33]> {
    coeffs
        .iter()
        .map(|c| serialize_element(&scalar_base_multi(c)))
        .collect()
}

/// Merge two sets of VSS commitments by adding corresponding points.
/// Mirrors `merge_share_commits` in the TS implementation.
pub fn merge_share_commits(
    commits_a: &[[u8; 33]],
    commits_b: &[[u8; 33]],
) -> Result<Vec<[u8; 33]>, Error> {
    assert::equal_arr_size(commits_a, commits_b)?;
    commits_a
        .iter()
        .zip(commits_b.iter())
        .map(|(a, b)| {
            let pa = crate::ecc::util::lift_x(a)?;
            let pb = crate::ecc::util::lift_x(b)?;
            let pc = pa + pb;
            Ok(serialize_element(&pc))
        })
        .collect()
}
