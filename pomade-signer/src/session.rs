#![allow(dead_code)]

/// Bridges the hex-string schema types (GroupPackage, SharePackage, SignRequest)
/// to frost-taproot's byte-array types, implementing the bifrost session logic.
use frost_taproot::{
    context::get_group_signing_ctx,
    ecdh::create_ecdh_share,
    helpers::{get_pubkey, tweak_pubkey, tweak_seckey},
    sign::sign_msg,
    types::{PublicNonce, SecretNonce, SecretShare},
    Error,
};
use sha2::{Digest, Sha256};

use crate::schema::{
    Commit, EcdhRequest, EcdhResult, Group, Hex32, PsigEntry, Share, SignRequest, SignResult,
};

fn decode32(s: &str) -> Result<[u8; 32], String> {
    let b = hex::decode(s).map_err(|e| e.to_string())?;
    b.try_into()
        .map_err(|_| format!("expected 32 bytes, got {}", s.len() / 2))
}

fn decode33(s: &str) -> Result<[u8; 33], String> {
    let b = hex::decode(s).map_err(|e| e.to_string())?;
    b.try_into()
        .map_err(|_| format!("expected 33 bytes, got {}", s.len() / 2))
}

fn encode32(b: &[u8; 32]) -> String {
    hex::encode(b)
}

fn encode33(b: &[u8; 33]) -> String {
    hex::encode(b)
}

/// Check if a share belongs to a group (mirrors `Lib.is_group_member`).
pub fn is_group_member(group: &Group, share: &Share) -> bool {
    let Ok(seckey) = decode32(&share.seckey.0) else {
        return false;
    };
    let pubkey = get_pubkey(&seckey);
    let pubkey_hex = encode33(&pubkey);
    group
        .commits
        .0
        .iter()
        .any(|c| c.idx == share.idx && c.pubkey.0 == pubkey_hex)
}

/// Compute the sighash binder: SHA-256(session_id || member_idx_be32 || sighash_vec_concat).
/// Mirrors `get_sighash_binder` in bifrost.
fn get_sighash_binder(session_id: &[u8; 32], member_idx: u32, sigvec: &[Hex32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(session_id);
    hasher.update(member_idx.to_be_bytes());
    for h in sigvec {
        if let Ok(b) = hex::decode(&h.0) {
            hasher.update(&b);
        }
    }
    hasher.finalize().into()
}

/// Tweak a commit's public nonces for a given sighash vector.
/// Mirrors `create_sighash_commit` in bifrost.
fn tweak_commit_pnonces(
    commit: &Commit,
    session_id: &[u8; 32],
    sigvec: &[Hex32],
) -> Result<PublicNonce, Error> {
    let bind_hash = get_sighash_binder(session_id, commit.idx, sigvec);
    let hidden_pn = tweak_pubkey(
        &decode33(&commit.hidden_pn.0).map_err(|_| Error::InvalidPoint)?,
        &bind_hash,
    )?;
    let binder_pn = tweak_pubkey(
        &decode33(&commit.binder_pn.0).map_err(|_| Error::InvalidPoint)?,
        &bind_hash,
    )?;
    Ok(PublicNonce {
        idx: commit.idx,
        hidden_pn,
        binder_pn,
    })
}

/// Tweak a share's secret nonces for a given sighash vector.
/// Mirrors `create_sighash_share` in bifrost.
fn tweak_share_snonces(
    share: &Share,
    session_id: &[u8; 32],
    sigvec: &[Hex32],
) -> Result<SecretNonce, Error> {
    let bind_hash = get_sighash_binder(session_id, share.idx, sigvec);
    let hidden_sn = tweak_seckey(
        &decode32(&share.hidden_sn.0).map_err(|_| Error::InvalidPoint)?,
        &bind_hash,
    );
    let binder_sn = tweak_seckey(
        &decode32(&share.binder_sn.0).map_err(|_| Error::InvalidPoint)?,
        &bind_hash,
    );
    Ok(SecretNonce {
        idx: share.idx,
        hidden_sn,
        binder_sn,
    })
}

/// Per-sighash signing context: the frost-taproot GroupSigningCtx plus the sighash it covers.
struct SighashCtx {
    sighash: [u8; 32],
    ctx: frost_taproot::types::GroupSigningCtx,
}

/// Build all per-sighash contexts for a sign request (mirrors `get_session_ctx` in bifrost).
fn build_sighash_contexts(
    group: &Group,
    request: &crate::schema::SignRequestInner,
    session_id: &[u8; 32],
) -> Result<Vec<SighashCtx>, Error> {
    let group_pk = decode33(&group.group_pk.0).map_err(|_| Error::InvalidPoint)?;
    let mut result = Vec::new();

    for sigvec in &request.hashes.0 {
        let hashes = &sigvec.0;
        let sighash = decode32(&hashes[0].0).map_err(|_| Error::InvalidPoint)?;
        let tweaks: Vec<[u8; 32]> = hashes[1..]
            .iter()
            .filter_map(|h| decode32(&h.0).ok())
            .collect();

        // Build tweaked public nonces for each member in this session
        let pnonces: Vec<PublicNonce> = request
            .members
            .0
            .iter()
            .filter_map(|&idx| group.commits.0.iter().find(|c| c.idx == idx))
            .filter_map(|commit| tweak_commit_pnonces(commit, session_id, hashes).ok())
            .collect();

        let ctx = get_group_signing_ctx(&group_pk, &pnonces, &sighash, &tweaks)?;
        result.push(SighashCtx { sighash, ctx });
    }

    Ok(result)
}

/// Compute the session ID from the group ID and session template fields.
/// Mirrors `get_session_id` in bifrost.
fn compute_session_id(group: &Group, request: &crate::schema::SignRequestInner) -> [u8; 32] {
    // group_id = SHA-256(commits_prefix || group_pk)
    let group_id = compute_group_id(group);

    let mut hasher = Sha256::new();
    hasher.update(&group_id);
    for &m in &request.members.0 {
        hasher.update(m.to_be_bytes());
    }
    for sigvec in &request.hashes.0 {
        for h in &sigvec.0 {
            if let Ok(b) = hex::decode(&h.0) {
                hasher.update(&b);
            }
        }
    }
    if let Some(content) = &request.content {
        hasher.update(content.as_bytes());
    } else {
        hasher.update(b"\x00");
    }
    hasher.update(request.kind.as_bytes());
    hasher.update(request.stamp.to_be_bytes());
    hasher.finalize().into()
}

/// Compute the group ID from a group package.
/// Mirrors `get_group_id` in bifrost: SHA-256(commits_prefix || group_pk).
fn compute_group_id(group: &Group) -> [u8; 32] {
    let mut sorted = group.commits.0.clone();
    sorted.sort_by_key(|c| c.idx);

    let mut prefix = Vec::new();
    for c in &sorted {
        prefix.extend_from_slice(&c.idx.to_be_bytes());
        if let Ok(b) = hex::decode(&c.hidden_pn.0) {
            prefix.extend_from_slice(&b);
        }
        if let Ok(b) = hex::decode(&c.binder_pn.0) {
            prefix.extend_from_slice(&b);
        }
    }

    let mut hasher = Sha256::new();
    hasher.update(&prefix);
    if let Ok(b) = hex::decode(&group.group_pk.0) {
        hasher.update(&b);
    }
    hasher.finalize().into()
}

/// Verify that the request's gid/sid match what we'd compute from the group.
pub fn verify_session_pkg(group: &Group, request: &crate::schema::SignRequestInner) -> bool {
    let gid = compute_group_id(group);
    let sid = compute_session_id(group, request);
    hex::encode(gid) == request.gid.0 && hex::encode(sid) == request.sid.0
}

/// Create a partial signature package for a sign request (mirrors `Lib.create_psig_pkg`).
pub fn create_psig_pkg(
    group: &Group,
    request: &SignRequest,
    share: &Share,
) -> Result<SignResult, Error> {
    let session_id = compute_session_id(group, &request.request);
    let sighash_ctxs = build_sighash_contexts(group, &request.request, &session_id)?;

    let seckey = decode32(&share.seckey.0).map_err(|_| Error::InvalidPoint)?;
    let pubkey = get_pubkey(&seckey);
    let secret_share = SecretShare {
        idx: share.idx,
        seckey,
    };

    let mut psigs: Vec<PsigEntry> = Vec::new();

    let sighash_hex = sighash_ctxs
        .iter()
        .map(|sc| hex::encode(sc.sighash))
        .collect::<Vec<_>>();
    for (sc, sc_hex) in sighash_ctxs.iter().zip(sighash_hex.iter()) {
        let sigvec = request
            .request
            .hashes
            .0
            .iter()
            .find(|v| v.0.first().map(|h| &h.0) == Some(sc_hex))
            .map(|v| v.0.as_slice())
            .unwrap_or_default();
        let snonce = tweak_share_snonces(share, &session_id, sigvec)?;

        let sig = sign_msg(&sc.ctx, &secret_share, &snonce)?;
        psigs.push((
            crate::schema::Hex32(hex::encode(sc.sighash)),
            crate::schema::Hex32(hex::encode(sig.psig)),
        ));
    }

    Ok(SignResult {
        idx: share.idx,
        psigs,
        pubkey: crate::schema::Hex33(encode33(&pubkey)),
        sid: crate::schema::Hex32(hex::encode(session_id)),
    })
}

/// Create an ECDH package (mirrors `Lib.create_ecdh_pkg`).
pub fn create_ecdh_pkg(request: &EcdhRequest, share: &Share) -> Result<EcdhResult, Error> {
    let seckey = decode32(&share.seckey.0).map_err(|_| Error::InvalidPoint)?;
    let ecdh_pk = decode33(&request.ecdh_pk.0).map_err(|_| Error::InvalidPoint)?;
    let secret_share = SecretShare {
        idx: share.idx,
        seckey,
    };
    let members: Vec<u32> = request.members.0.clone();

    let ecdh_share = create_ecdh_share(&members, &secret_share, &ecdh_pk)?;

    Ok(EcdhResult {
        idx: ecdh_share.idx,
        keyshare: crate::schema::Hex(encode33(&ecdh_share.pubkey)),
        members: crate::schema::BoundedVec(members),
        ecdh_pk: crate::schema::Hex(hex::encode(&ecdh_pk)),
    })
}
