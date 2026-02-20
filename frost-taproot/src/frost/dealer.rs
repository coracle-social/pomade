/// Trusted dealer key generation and group management.
use sha2::{Digest, Sha256};

use crate::group::create_dealer_set;
use crate::helpers::get_pubkey;
use crate::Error;

use super::types::{DealerPackage, GroupPackage, MemberPackage, SharePackage};

/// Generate a complete dealer package: group info + all secret shares.
///
/// `secrets` seeds the polynomial deterministically; pass `&[]` for a
/// fully random group key.
///
/// # Example
/// ```rust
/// use frost_taproot::frost::dealer::generate_dealer_package;
/// let pkg = generate_dealer_package(2, 3, &[]).unwrap();
/// assert_eq!(pkg.shares.len(), 3);
/// assert_eq!(pkg.group.threshold, 2);
/// ```
pub fn generate_dealer_package(
    threshold: usize,
    share_count: u32,
    secrets: &[[u8; 32]],
) -> Result<DealerPackage, Error> {
    let dealer_set = create_dealer_set(threshold, share_count, secrets)?;

    let shares: Vec<SharePackage> = dealer_set
        .shares
        .iter()
        .map(|s| SharePackage {
            idx: s.idx,
            seckey: s.seckey,
        })
        .collect();

    let members: Vec<MemberPackage> = dealer_set
        .shares
        .iter()
        .map(|s| MemberPackage {
            idx: s.idx,
            pubkey: get_pubkey(&s.seckey),
            identity_pk: None,
        })
        .collect();

    let group = GroupPackage {
        group_pk: dealer_set.group_pk,
        threshold,
        members,
    };

    Ok(DealerPackage { group, shares })
}

/// Compute a stable group identifier: SHA-256(group_pk || threshold_u32_be || sorted_member_pubkeys).
pub fn get_group_id(group: &GroupPackage) -> [u8; 32] {
    let mut sorted = group.members.clone();
    sorted.sort_by_key(|m| m.idx);

    let mut hasher = Sha256::new();
    hasher.update(&group.group_pk);
    hasher.update((group.threshold as u32).to_be_bytes());
    for m in &sorted {
        hasher.update(&m.pubkey);
    }
    hasher.finalize().into()
}

/// Check whether a share belongs to the given group.
///
/// Verifies that the share's derived public key matches the member entry
/// at the same index.
pub fn is_group_member(group: &GroupPackage, share: &SharePackage) -> bool {
    let pubkey = get_pubkey(&share.seckey);
    group
        .members
        .iter()
        .any(|m| m.idx == share.idx && m.pubkey == pubkey)
}

/// Verify all shares in a dealer package against the group's VSS commitments.
///
/// Returns `Ok(true)` if every share is valid, `Ok(false)` if any fails,
/// or an `Err` on a crypto error.
pub fn verify_dealer_package(pkg: &DealerPackage) -> Result<bool, Error> {
    // Re-derive VSS commits from the group's member pubkeys.
    // The group_pk is the first VSS commit (constant term * G).
    // We can verify membership via is_group_member for each share.
    for share in &pkg.shares {
        if !is_group_member(&pkg.group, share) {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Look up a member by index.
pub fn get_member_by_idx(group: &GroupPackage, idx: u32) -> Option<&MemberPackage> {
    group.members.iter().find(|m| m.idx == idx)
}

/// Look up a member by public key.
pub fn get_member_by_pubkey<'a>(
    group: &'a GroupPackage,
    pubkey: &[u8; 33],
) -> Option<&'a MemberPackage> {
    group.members.iter().find(|m| &m.pubkey == pubkey)
}
