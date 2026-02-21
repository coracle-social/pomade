// Mirrors ref/frost/src/lib/recover.ts

use k256::Scalar;

use crate::Error;
use crate::ecc::util::{scalar_from_bytes, scalar_to_bytes};
use crate::poly::{calc_lagrange_coeff, index_to_scalar};
use crate::types::{SecretShare, SecretSharePackage};
use crate::util::assert;
use crate::vss::{create_share_coeffs, get_share_commits};

/// Generate recovery shares that allow a target participant to reconstruct their share.
/// Mirrors `gen_recovery_shares` in the TS implementation.
pub fn gen_recovery_shares(
    members: &[u32],
    share: &SecretShare,
    target: u32,
    threshold: usize,
    secrets: &[[u8; 32]],
) -> Result<SecretSharePackage, Error> {
    assert::ok(
        members.len() >= threshold,
        "not enough members to meet threshold",
    )?;

    let mut sorted_members = members.to_vec();
    sorted_members.sort();

    let share_idx = index_to_scalar(share.idx);
    let target_idx = index_to_scalar(target);

    // Members excluding the current share holder.
    let mbrs: Vec<Scalar> = sorted_members
        .iter()
        .filter(|&&idx| idx != share.idx)
        .map(|&idx| index_to_scalar(idx))
        .collect();

    let share_seckey = scalar_from_bytes(&share.seckey);
    let lgrng_coeff = calc_lagrange_coeff(&mbrs, share_idx, target_idx)?;

    assert::ok(
        lgrng_coeff != Scalar::ZERO,
        "lagrange coefficient must be greater than zero",
    )?;

    let rand_coeffs = create_share_coeffs(secrets, threshold - 1);
    let coeff_sum = rand_coeffs.iter().fold(Scalar::ZERO, |p, n| p + n);
    let repair_coeff = lgrng_coeff * share_seckey - coeff_sum;

    let repair_shares: Vec<Scalar> = rand_coeffs
        .iter()
        .cloned()
        .chain(std::iter::once(repair_coeff))
        .collect();

    let vss_commits = get_share_commits(&repair_shares);

    let shares: Vec<SecretShare> = sorted_members
        .iter()
        .enumerate()
        .map(|(i, &idx)| SecretShare {
            idx,
            seckey: scalar_to_bytes(&repair_shares[i]),
        })
        .collect();

    Ok(SecretSharePackage {
        idx: share.idx,
        vss_commits,
        shares,
    })
}

/// Recover a participant's share by summing aggregated recovery shares.
/// Mirrors `recover_share` in the TS implementation.
pub fn recover_share(shares: &[SecretShare], idx: u32) -> SecretShare {
    let summed = shares
        .iter()
        .map(|s| scalar_from_bytes(&s.seckey))
        .fold(Scalar::ZERO, |p, n| p + n);
    SecretShare {
        idx,
        seckey: scalar_to_bytes(&summed),
    }
}
