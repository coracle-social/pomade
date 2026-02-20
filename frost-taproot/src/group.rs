// Mirrors ref/frost/src/lib/group.ts
// High-level share set creation (trusted dealer).

use crate::shares::create_shares;
use crate::types::{DealerShareSet, SecretShareSet};
use crate::vss::{create_share_coeffs, get_share_commits};
use crate::Error;

/// Create a set of secret shares and VSS commitments.
/// Mirrors `create_share_set` in the TS implementation.
pub fn create_share_set(
    threshold: usize,
    share_max: u32,
    secrets: &[[u8; 32]],
) -> Result<SecretShareSet, Error> {
    let coeffs = create_share_coeffs(secrets, threshold);
    let shares = create_shares(&coeffs, share_max)?;
    let vss_commits = get_share_commits(&coeffs);
    Ok(SecretShareSet {
        shares,
        vss_commits,
    })
}

/// Create a dealer share set that also exposes the group public key.
/// The group public key is the first VSS commitment (the constant term's public key).
/// Mirrors `create_dealer_set` in the TS implementation.
pub fn create_dealer_set(
    threshold: usize,
    share_max: u32,
    secrets: &[[u8; 32]],
) -> Result<DealerShareSet, Error> {
    let share_set = create_share_set(threshold, share_max, secrets)?;
    let group_pk = share_set.vss_commits[0];
    Ok(DealerShareSet {
        shares: share_set.shares,
        vss_commits: share_set.vss_commits,
        group_pk,
    })
}
