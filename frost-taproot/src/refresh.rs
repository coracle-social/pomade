// Mirrors ref/frost/src/lib/refresh.ts

use k256::Scalar;

use crate::shares::{combine_set, create_shares};
use crate::types::{SecretShare, SecretSharePackage};
use crate::vss::{create_share_coeffs, get_share_commits};
use crate::Error;

/// Generate refresh shares for proactive secret sharing.
/// The polynomial has a zero constant term, so adding these shares to existing
/// shares does not change the underlying secret.
/// Mirrors `gen_refresh_shares` in the TS implementation.
pub fn gen_refresh_shares(
    index: u32,
    threshold: usize,
    share_max: u32,
    secrets: &[[u8; 32]],
) -> Result<SecretSharePackage, Error> {
    // Auxiliary coefficients (threshold - 1 of them, no constant term).
    let sub_coeffs = create_share_coeffs(secrets, threshold - 1);
    // Prepend zero as the constant term so the polynomial evaluates to 0 at x=0.
    let coeffs: Vec<Scalar> = std::iter::once(Scalar::ZERO)
        .chain(sub_coeffs.iter().cloned())
        .collect();

    let shares = create_shares(&coeffs, share_max)?;
    let vss_commits = get_share_commits(&sub_coeffs);

    Ok(SecretSharePackage {
        idx: index,
        vss_commits,
        shares,
    })
}

/// Apply refresh shares to a current share by summing them.
/// Mirrors `refresh_share` in the TS implementation.
pub fn refresh_share(
    refresh_shares: &[SecretShare],
    current_share: &SecretShare,
) -> Result<SecretShare, Error> {
    let all: Vec<SecretShare> = std::iter::once(current_share.clone())
        .chain(refresh_shares.iter().cloned())
        .collect();
    combine_set(&all)
}
