// Mirrors ref/frost/src/lib/shares.ts

use k256::{elliptic_curve::point::AffineCoordinates, Scalar};

use crate::ecc::group::{scalar_base_multi, scalar_multi};
use crate::ecc::util::{lift_x, pow_n, scalar_from_bytes, scalar_to_bytes};
use crate::poly::{evaluate_x, index_to_scalar, interpolate_root};
use crate::types::SecretShare;
use crate::util::assert;
use crate::Error;

/// Create secret shares by evaluating the polynomial at indices 1..=count.
/// Mirrors `create_shares` in the TS implementation.
pub fn create_shares(coeffs: &[Scalar], count: u32) -> Result<Vec<SecretShare>, Error> {
    let mut shares = Vec::with_capacity(count as usize);
    for i in 1..=count {
        let x = index_to_scalar(i);
        let scalar = evaluate_x(coeffs, x)?;
        shares.push(SecretShare {
            idx: i,
            seckey: scalar_to_bytes(&scalar),
        });
    }
    Ok(shares)
}

/// Sum a list of secret shares into a single scalar (used in DKG aggregation).
/// Mirrors `combine_shares` in the TS implementation.
pub fn combine_shares(shares: &[SecretShare]) -> [u8; 32] {
    let secret = shares
        .iter()
        .map(|s| scalar_from_bytes(&s.seckey))
        .fold(Scalar::ZERO, |acc, cur| acc + cur);
    scalar_to_bytes(&secret)
}

/// Combine a set of shares that all have the same idx into one share.
/// Mirrors `combine_set` in the TS implementation.
pub fn combine_set(shares: &[SecretShare]) -> Result<SecretShare, Error> {
    assert::is_equal_set(&shares.iter().map(|s| s.idx).collect::<Vec<_>>())?;
    let idx = shares[0].idx;
    let seckey = combine_shares(shares);
    Ok(SecretShare { idx, seckey })
}

/// Merge two lists of shares by combining matching indices.
/// Mirrors `merge_shares` in the TS implementation.
pub fn merge_shares(
    shares_a: &[SecretShare],
    shares_b: &[SecretShare],
) -> Result<Vec<SecretShare>, Error> {
    assert::equal_arr_size(shares_a, shares_b)?;
    shares_a
        .iter()
        .map(|curr| {
            let aux = shares_b
                .iter()
                .find(|s| s.idx == curr.idx)
                .ok_or(Error::RecordNotFound(curr.idx))?;
            combine_set(&[curr.clone(), aux.clone()])
        })
        .collect()
}

/// Verify a secret share against VSS commitments.
/// Mirrors `verify_share` in the TS implementation.
pub fn verify_share(
    commits: &[[u8; 33]],
    share: &SecretShare,
    threshold: usize,
) -> Result<bool, Error> {
    let scalar = scalar_from_bytes(&share.seckey);
    let s_i = scalar_base_multi(&scalar);

    let mut s_ip = None;
    for j in 0..threshold {
        let point = lift_x(&commits[j])?;
        let exp = pow_n(share.idx as u64, j as u64);
        let prod = scalar_multi(&point, &exp);
        s_ip = Some(match s_ip {
            None => prod,
            Some(acc) => acc + prod,
        });
    }

    let s_ip = s_ip.ok_or(Error::Assertion("no commits".to_string()))?;

    // Compare x-coordinates (affine).
    let s_i_affine = s_i.to_affine();
    let s_ip_affine = s_ip.to_affine();
    Ok(s_i_affine.x() == s_ip_affine.x())
}

/// Recover the group secret by Lagrange interpolation over a threshold of shares.
/// Mirrors `derive_shares_secret` in the TS implementation.
pub fn derive_shares_secret(shares: &[SecretShare]) -> Result<[u8; 32], Error> {
    let points: Vec<(Scalar, Scalar)> = shares
        .iter()
        .map(|s| (index_to_scalar(s.idx), scalar_from_bytes(&s.seckey)))
        .collect();
    let secret = interpolate_root(&points)?;
    Ok(scalar_to_bytes(&secret))
}
