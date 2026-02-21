/// High-level signing session management and partial signature operations.
use sha2::{Digest, Sha256};

use crate::Error;
use crate::context::get_group_signing_ctx;
use crate::sign::{
    combine_partial_sigs as low_combine, sign_msg, verify_final_sig,
    verify_partial_sig as low_verify,
};
use crate::types::{
    PublicNonce as LowPublicNonce, SecretNonce as LowSecretNonce, SecretShare as LowSecretShare,
    ShareSignature,
};

use super::dealer::get_group_id;
use super::types::{
    GroupPackage, MemberNonce, PartialSig, PartialSigPackage, SecretNoncePair, SharePackage,
    SignSession, Signature,
};

/// Create a signing session for a set of messages and participating members.
///
/// `messages` is a list of `(message_bytes, tweaks)` pairs. Tweaks are
/// applied to the group key before signing (e.g. for BIP-32 derivation).
/// `nonces` must contain one `MemberNonce` per participating member.
///
/// The session ID is deterministically derived from the group ID, members,
/// and messages, making it safe to compare sessions across participants.
pub fn create_sign_session(
    group: &GroupPackage,
    members: Vec<u32>,
    messages: Vec<(Vec<u8>, Vec<[u8; 32]>)>,
    nonces: Vec<MemberNonce>,
) -> Result<SignSession, Error> {
    if nonces.len() != members.len() {
        return Err(Error::Assertion(format!(
            "nonce count ({}) must equal member count ({})",
            nonces.len(),
            members.len()
        )));
    }

    let mut sorted_members = members;
    sorted_members.sort();

    let sid = compute_session_id(group, &sorted_members, &messages);

    Ok(SignSession {
        sid,
        group_pk: group.group_pk,
        members: sorted_members,
        messages,
        nonces,
    })
}

/// Compute a deterministic session ID:
/// SHA-256(group_id || members[4B each] || messages[len+bytes+tweaks])
fn compute_session_id(
    group: &GroupPackage,
    members: &[u32],
    messages: &[(Vec<u8>, Vec<[u8; 32]>)],
) -> [u8; 32] {
    let gid = get_group_id(group);
    let mut hasher = Sha256::new();
    hasher.update(gid);
    for &m in members {
        hasher.update(m.to_be_bytes());
    }
    for (msg, tweaks) in messages {
        hasher.update((msg.len() as u32).to_be_bytes());
        hasher.update(msg);
        for t in tweaks {
            hasher.update(t);
        }
    }
    hasher.finalize().into()
}

/// Produce a partial signature package for all messages in a session.
///
/// The caller provides the `SecretNoncePair` for their slot in the session
/// (re-derived from the stored code via [`crate::frost::nonce::derive_secret_nonce`]).
pub fn create_partial_sig_package(
    session: &SignSession,
    share: &SharePackage,
    secret_nonce: &SecretNoncePair,
) -> Result<PartialSigPackage, Error> {
    let low_share = LowSecretShare {
        idx: share.idx,
        seckey: share.seckey,
    };
    let low_snonce = LowSecretNonce {
        idx: share.idx,
        binder_sn: secret_nonce.binder_sn,
        hidden_sn: secret_nonce.hidden_sn,
    };

    let pnonces = build_public_nonces(&session.nonces);
    let mut psigs = Vec::with_capacity(session.messages.len());

    for (message, tweaks) in &session.messages {
        let ctx = get_group_signing_ctx(&session.group_pk, &pnonces, message, tweaks)?;
        let sig = sign_msg(&ctx, &low_share, &low_snonce)?;
        psigs.push(PartialSig {
            message: message.clone(),
            psig: sig.psig,
        });
    }

    let pubkey = crate::helpers::get_pubkey(&share.seckey);

    Ok(PartialSigPackage {
        idx: share.idx,
        pubkey,
        sid: session.sid,
        psigs,
    })
}

/// Verify a partial signature package from one member.
///
/// Returns `Ok(None)` if valid, or `Ok(Some(reason))` if invalid.
pub fn verify_partial_sig_package(
    session: &SignSession,
    group: &GroupPackage,
    pkg: &PartialSigPackage,
) -> Result<Option<String>, Error> {
    if pkg.sid != session.sid {
        return Ok(Some("session id mismatch".to_string()));
    }

    let member_pubkeys: Vec<[u8; 33]> = group.members.iter().map(|m| m.pubkey).collect();
    if !member_pubkeys.contains(&pkg.pubkey) {
        return Ok(Some("pubkey not found in group".to_string()));
    }

    let pnonces = build_public_nonces(&session.nonces);
    let pnonce = match pnonces.iter().find(|n| n.idx == pkg.idx) {
        Some(n) => n,
        None => return Ok(Some(format!("no nonce for member {}", pkg.idx))),
    };

    for (i, (message, tweaks)) in session.messages.iter().enumerate() {
        let psig_entry = match pkg.psigs.get(i) {
            Some(e) => e,
            None => return Ok(Some(format!("missing partial sig for message {i}"))),
        };

        let ctx = get_group_signing_ctx(&session.group_pk, &pnonces, message, tweaks)?;

        if !low_verify(&ctx, pnonce, &pkg.pubkey, &psig_entry.psig)? {
            return Ok(Some(format!("partial sig invalid for message {i}")));
        }
    }

    Ok(None)
}

/// Combine partial signature packages into final BIP340 signatures.
///
/// All packages must cover the same session. Returns one `Signature`
/// per message in the session. The combined signatures are verified
/// before being returned.
pub fn combine_signatures(
    session: &SignSession,
    group: &GroupPackage,
    pkgs: &[PartialSigPackage],
) -> Result<Vec<Signature>, Error> {
    if pkgs.len() < group.threshold {
        return Err(Error::Assertion(format!(
            "need at least {} partial sigs, got {}",
            group.threshold,
            pkgs.len()
        )));
    }

    let pnonces = build_public_nonces(&session.nonces);
    let mut signatures = Vec::with_capacity(session.messages.len());

    for (i, (message, tweaks)) in session.messages.iter().enumerate() {
        let ctx = get_group_signing_ctx(&session.group_pk, &pnonces, message, tweaks)?;

        let share_sigs: Vec<ShareSignature> = pkgs
            .iter()
            .map(|pkg| {
                let psig = pkg.psigs.get(i).ok_or_else(|| {
                    Error::Assertion(format!(
                        "missing psig at index {i} in pkg from member {}",
                        pkg.idx
                    ))
                })?;
                Ok(ShareSignature {
                    idx: pkg.idx,
                    pubkey: pkg.pubkey,
                    psig: psig.psig,
                })
            })
            .collect::<Result<_, Error>>()?;

        let sig = low_combine(&ctx, &share_sigs)?;

        let key_ctx = ctx.key_context();
        if !verify_final_sig(&key_ctx, message, &sig)? {
            return Err(Error::Assertion(format!(
                "combined signature failed BIP340 verification for message {i}"
            )));
        }

        signatures.push(Signature {
            message: message.clone(),
            pubkey: ctx.group_pk,
            sig,
        });
    }

    Ok(signatures)
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn build_public_nonces(nonces: &[MemberNonce]) -> Vec<LowPublicNonce> {
    nonces
        .iter()
        .map(|n| LowPublicNonce {
            idx: n.idx,
            binder_pn: n.binder_pn,
            hidden_pn: n.hidden_pn,
        })
        .collect()
}
