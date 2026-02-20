// Mirrors ref/frost/src/lib/commit.ts

use crate::ecc::group::{scalar_multi, serialize_element, serialize_scalar_u32};
use crate::ecc::hash::{h1, h4, h5};
use crate::ecc::util::lift_x;
use crate::helpers::{generate_nonce, get_pubkey};
use crate::types::{BindFactor, CommitmentPackage, PublicNonce, SecretShare};
use crate::Error;

/// Extract participant indices from a list of public nonces.
/// Mirrors `get_nonce_ids` in the TS implementation.
pub fn get_nonce_ids(pnonces: &[PublicNonce]) -> Vec<u32> {
    pnonces.iter().map(|pn| pn.idx).collect()
}

/// Encode all public nonces into a sorted byte prefix.
/// Mirrors `get_commits_prefix` in the TS implementation.
pub fn get_commits_prefix(pnonces: &[PublicNonce]) -> Vec<u8> {
    let mut sorted = pnonces.to_vec();
    sorted.sort_by_key(|pn| pn.idx);

    let mut out = Vec::new();
    for pn in &sorted {
        out.extend_from_slice(&serialize_scalar_u32(pn.idx));
        out.extend_from_slice(&pn.hidden_pn);
        out.extend_from_slice(&pn.binder_pn);
    }
    out
}

/// Build the group signing prefix: group_pk || H4(msg) || H5(commit_list).
/// Mirrors `get_group_prefix` in the TS implementation.
pub fn get_group_prefix(pnonces: &[PublicNonce], group_pk: &[u8; 33], message: &[u8]) -> Vec<u8> {
    let msg_hash = h4(message);
    let commit_list = get_commits_prefix(pnonces);
    let commit_hash = h5(&commit_list);

    let mut out = Vec::new();
    out.extend_from_slice(group_pk);
    out.extend_from_slice(&msg_hash);
    out.extend_from_slice(&commit_hash);
    out
}

/// Look up the binding factor for a given participant index.
/// Mirrors `get_bind_factor` in the TS implementation.
pub fn get_bind_factor(binders: &[BindFactor], idx: u32) -> Result<[u8; 32], Error> {
    binders
        .iter()
        .find(|b| b.idx == idx)
        .map(|b| b.factor)
        .ok_or(Error::RecordNotFound(idx))
}

/// Compute per-participant binding factors from the group prefix.
/// Mirrors `get_group_binders` in the TS implementation.
pub fn get_group_binders(pnonces: &[PublicNonce], prefix: &[u8]) -> Vec<BindFactor> {
    pnonces
        .iter()
        .map(|pn| {
            let scalar_bytes = serialize_scalar_u32(pn.idx);
            let mut rho_input = prefix.to_vec();
            rho_input.extend_from_slice(&scalar_bytes);
            let factor = h1(&rho_input);
            BindFactor {
                idx: pn.idx,
                factor,
            }
        })
        .collect()
}

/// Compute the group public nonce: sum of (hidden_pn + bind_factor * binder_pn) for each participant.
/// Mirrors `get_group_pubnonce` in the TS implementation.
pub fn get_group_pubnonce(
    pnonces: &[PublicNonce],
    binders: &[BindFactor],
) -> Result<[u8; 33], Error> {
    use crate::ecc::group::element_add;
    use crate::ecc::util::scalar_from_bytes;

    let mut group_commit = None;

    for pn in pnonces {
        let hidden_elem = lift_x(&pn.hidden_pn)?;
        let binding_elem = lift_x(&pn.binder_pn)?;
        let bind_factor_bytes = get_bind_factor(binders, pn.idx)?;
        let bind_factor = scalar_from_bytes(&bind_factor_bytes);
        let factored_elem = scalar_multi(&binding_elem, &bind_factor);
        group_commit = Some(element_add(group_commit, Some(hidden_elem))?);
        group_commit = Some(element_add(group_commit, Some(factored_elem))?);
    }

    let pt = group_commit.ok_or(Error::BothPointsNull)?;
    Ok(serialize_element(&pt))
}

/// Create a commitment package (secret + public nonces) for a signing session.
/// Mirrors `create_commit_pkg` in the TS implementation.
pub fn create_commit_pkg(
    secret_share: &SecretShare,
    hidden_seed: Option<&[u8; 32]>,
    binder_seed: Option<&[u8; 32]>,
) -> CommitmentPackage {
    let binder_sn = generate_nonce(&secret_share.seckey, binder_seed);
    let hidden_sn = generate_nonce(&secret_share.seckey, hidden_seed);
    let binder_pn = get_pubkey(&binder_sn);
    let hidden_pn = get_pubkey(&hidden_sn);
    CommitmentPackage {
        idx: secret_share.idx,
        binder_sn,
        hidden_sn,
        binder_pn,
        hidden_pn,
    }
}

/// Find a commitment package for a given share.
/// Mirrors `get_commit_pkg` in the TS implementation.
pub fn get_commit_pkg(
    commits: &[CommitmentPackage],
    share: &SecretShare,
) -> Result<CommitmentPackage, Error> {
    commits
        .iter()
        .find(|c| c.idx == share.idx)
        .cloned()
        .ok_or(Error::RecordNotFound(share.idx))
}
