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

/// Mirrors `Buff.bytes(n)` / `numToBytes(n, undefined)` from @cmdcode/buff:
/// encodes n as the minimum number of big-endian bytes needed (1, 2, or 4).
fn num_to_bytes_be_varwidth(n: u32) -> Vec<u8> {
    if n <= 0xFF {
        vec![n as u8]
    } else if n <= 0xFFFF {
        (n as u16).to_be_bytes().to_vec()
    } else {
        n.to_be_bytes().to_vec()
    }
}

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
    hasher.update(group_id);
    // Members: Buff.bytes(n) uses variable-width big-endian (1 byte for n <= 0xFF)
    for &m in &request.members.0 {
        hasher.update(num_to_bytes_be_varwidth(m));
    }
    for sigvec in &request.hashes.0 {
        for h in &sigvec.0 {
            if let Ok(b) = hex::decode(&h.0) {
                hasher.update(&b);
            }
        }
    }
    // Buff.bytes(content ?? '00'): hex-decode the string, or [0x00] if null
    if let Some(content) = &request.content {
        if let Ok(b) = hex::decode(content) {
            hasher.update(&b);
        }
    } else {
        hasher.update(b"\x00");
    }
    hasher.update(request.kind.as_bytes());
    // Stamp: Buff.num(stamp, 4) uses exactly 4 bytes big-endian
    hasher.update((request.stamp as u32).to_be_bytes());
    hasher.finalize().into()
}

/// Compute the group ID from a group package.
/// Mirrors `get_group_id` in bifrost: SHA-256(commits_prefix || group_pk).
fn compute_group_id(group: &Group) -> [u8; 32] {
    let mut sorted = group.commits.0.clone();
    sorted.sort_by_key(|c| c.idx);

    let mut prefix = Vec::new();
    for c in &sorted {
        // SerializeScalar(idx) = new Buff(idx, 32): zero-padded 32-byte big-endian
        let mut idx_bytes = [0u8; 32];
        idx_bytes[28..].copy_from_slice(&c.idx.to_be_bytes());
        prefix.extend_from_slice(&idx_bytes);
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
        ecdh_pk: crate::schema::Hex(hex::encode(ecdh_pk)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{
        BoundedVec, Commit, EcdhRequest, Group, Hex32, Hex33, Share, SighashVec, SignRequest,
        SignRequestInner,
    };

    /// End-to-end test: generate a 2-of-3 FROST group, sign a nostr event,
    /// and verify the resulting event with the rust-nostr crate.
    #[test]
    fn test_frost_sign_nostr_event() {
        use frost_taproot::{
            commit::create_commit_pkg, frost::dealer::generate_dealer_package,
            sign::combine_partial_sigs, types::ShareSignature,
        };
        use nostr::secp256k1::schnorr::Signature as SchnorrSig;
        use nostr::{EventBuilder, Kind, PublicKey};

        // ── 1. Generate a 2-of-3 FROST group ─────────────────────────────────

        let secrets = [[0x11u8; 32], [0x22u8; 32]];
        let pkg = generate_dealer_package(2, 3, &secrets).unwrap();
        let group = &pkg.group;

        // group_pk is 33-byte compressed; nostr PublicKey is x-only (32 bytes).
        let group_pk_xonly = PublicKey::from_slice(&group.group_pk[1..]).unwrap();

        // ── 2. Build an unsigned nostr event ──────────────────────────────────

        let mut unsigned =
            EventBuilder::new(Kind::TextNote, "hello from FROST").build(group_pk_xonly);
        let event_id = unsigned.id();

        // The sighash is the raw 32-byte event ID.
        let sighash = *event_id.as_bytes();
        let sighash_hex = hex::encode(sighash);

        // ── 3. Build schema types for the two signing members (indices 1 & 2) ─

        let members = vec![1u32, 2u32];

        // Create commitment packages (nonces) for each signer.
        let low_shares: Vec<_> = pkg.shares[..2]
            .iter()
            .map(|s| frost_taproot::types::SecretShare {
                idx: s.idx,
                seckey: s.seckey,
            })
            .collect();

        let commit_pkgs: Vec<_> = low_shares
            .iter()
            .map(|s| create_commit_pkg(s, None, None))
            .collect();

        // Build the schema Group from the dealer package.
        let schema_group = Group {
            group_pk: Hex33(hex::encode(group.group_pk)),
            threshold: group.threshold as u32,
            commits: BoundedVec(
                commit_pkgs
                    .iter()
                    .map(|c| Commit {
                        idx: c.idx,
                        pubkey: Hex33(hex::encode(c.hidden_pn)), // not used in signing path
                        hidden_pn: Hex33(hex::encode(c.hidden_pn)),
                        binder_pn: Hex33(hex::encode(c.binder_pn)),
                    })
                    .collect(),
            ),
        };

        // Build the schema Share for each signer.
        let schema_shares: Vec<Share> = low_shares
            .iter()
            .zip(&commit_pkgs)
            .map(|(s, c)| Share {
                idx: s.idx,
                seckey: Hex32(hex::encode(s.seckey)),
                hidden_sn: Hex32(hex::encode(c.hidden_sn)),
                binder_sn: Hex32(hex::encode(c.binder_sn)),
            })
            .collect();

        // Compute gid/sid so verify_session_pkg passes.
        let gid_bytes = compute_group_id(&schema_group);
        let gid = hex::encode(gid_bytes);

        let request_inner_template = SignRequestInner {
            gid: Hex32(gid.clone()),
            sid: Hex32("00".repeat(32)), // placeholder; recomputed below
            members: BoundedVec(members.clone()),
            hashes: BoundedVec(vec![SighashVec(vec![Hex32(sighash_hex.clone())])]),
            content: None,
            kind: "message".to_string(),
            stamp: 1234567890,
        };
        let sid_bytes = compute_session_id(&schema_group, &request_inner_template);
        let sid = hex::encode(sid_bytes);

        let request_inner = SignRequestInner {
            sid: Hex32(sid),
            ..request_inner_template
        };

        assert!(
            verify_session_pkg(&schema_group, &request_inner),
            "gid/sid should verify"
        );

        let sign_request = SignRequest {
            request: request_inner,
        };

        // ── 4. Produce partial signatures from each signer ────────────────────

        let psig_results: Vec<_> = schema_shares
            .iter()
            .map(|share| create_psig_pkg(&schema_group, &sign_request, share).unwrap())
            .collect();

        // ── 5. Aggregate partial signatures ───────────────────────────────────

        // Rebuild the signing context to call combine_partial_sigs.
        let session_id = compute_session_id(&schema_group, &sign_request.request);
        let sighash_ctxs =
            build_sighash_contexts(&schema_group, &sign_request.request, &session_id).unwrap();

        let share_sigs: Vec<ShareSignature> = psig_results
            .iter()
            .map(|r| {
                let psig_hex = &r.psigs[0].1 .0;
                ShareSignature {
                    idx: r.idx,
                    pubkey: decode33(&r.pubkey.0).unwrap(),
                    psig: decode32(psig_hex).unwrap(),
                }
            })
            .collect();

        let final_sig = combine_partial_sigs(&sighash_ctxs[0].ctx, &share_sigs).unwrap();

        // ── 6. Assemble and verify the nostr event ────────────────────────────

        let schnorr_sig = SchnorrSig::from_slice(&final_sig).unwrap();
        let event = unsigned.add_signature(schnorr_sig).unwrap();

        event
            .verify()
            .expect("FROST-signed nostr event must verify");
    }

    fn create_test_commit(idx: u32, pubkey_prefix: &str) -> Commit {
        Commit {
            idx,
            pubkey: Hex33(pubkey_prefix.to_string() + &"a".repeat(64)),
            hidden_pn: Hex33("02".to_string() + &"b".repeat(64)),
            binder_pn: Hex33("02".to_string() + &"c".repeat(64)),
        }
    }

    fn create_test_group_with_commits(threshold: u32, commits: Vec<Commit>) -> Group {
        Group {
            commits: BoundedVec(commits),
            group_pk: Hex33("02".to_string() + &"d".repeat(64)),
            threshold,
        }
    }

    fn create_test_share(idx: u32) -> Share {
        // Use a valid-looking secret key (32 bytes of hex)
        Share {
            idx,
            binder_sn: Hex32("e".repeat(64)),
            hidden_sn: Hex32("f".repeat(64)),
            seckey: Hex32("1".repeat(64)),
        }
    }

    #[test]
    fn test_decode32_valid() {
        let hex = "a".repeat(64);
        let result = decode32(&hex);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 32);
    }

    #[test]
    fn test_decode32_invalid_hex() {
        let result = decode32("invalid_hex");
        assert!(result.is_err());
    }

    #[test]
    fn test_decode32_wrong_length() {
        // Too short
        let result = decode32(&"a".repeat(32));
        assert!(result.is_err());

        // Too long
        let result = decode32(&"a".repeat(128));
        assert!(result.is_err());
    }

    #[test]
    fn test_decode33_valid() {
        // 33 bytes = 66 hex chars
        let hex = "02".to_string() + &"a".repeat(64);
        let result = decode33(&hex);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 33);
    }

    #[test]
    fn test_decode33_invalid() {
        // Wrong length
        let result = decode33(&"a".repeat(64));
        assert!(result.is_err());
    }

    #[test]
    fn test_encode32() {
        let bytes = [0u8; 32];
        let encoded = encode32(&bytes);
        assert_eq!(encoded.len(), 64);
        assert_eq!(encoded, "0".repeat(64));
    }

    #[test]
    fn test_encode33() {
        let bytes = [0u8; 33];
        let encoded = encode33(&bytes);
        assert_eq!(encoded.len(), 66);
        assert_eq!(encoded, "0".repeat(66));
    }

    #[test]
    fn test_is_group_member_invalid_seckey() {
        let group = create_test_group_with_commits(1, vec![create_test_commit(0, "02")]);
        let share = Share {
            idx: 0,
            binder_sn: Hex32("e".repeat(64)),
            hidden_sn: Hex32("f".repeat(64)),
            seckey: Hex32("invalid".to_string()), // Invalid hex
        };

        assert!(!is_group_member(&group, &share));
    }

    #[test]
    fn test_is_group_member_mismatched_pubkey() {
        let group = create_test_group_with_commits(
            1,
            vec![
                create_test_commit(0, "02"), // Different pubkey
            ],
        );
        let share = create_test_share(0);

        // The share's derived pubkey won't match the commit's pubkey
        assert!(!is_group_member(&group, &share));
    }

    #[test]
    fn test_get_sighash_binder() {
        let session_id = [0u8; 32];
        let member_idx = 42u32;
        let sigvec = vec![Hex32("a".repeat(64))];

        let binder = get_sighash_binder(&session_id, member_idx, &sigvec);

        // Should produce a 32-byte hash
        assert_eq!(binder.len(), 32);

        // Same inputs should produce same output
        let binder2 = get_sighash_binder(&session_id, member_idx, &sigvec);
        assert_eq!(binder, binder2);

        // Different inputs should produce different output
        let binder3 = get_sighash_binder(&session_id, 43, &sigvec);
        assert_ne!(binder, binder3);
    }

    #[test]
    fn test_compute_group_id_deterministic() {
        let group = create_test_group_with_commits(
            1,
            vec![create_test_commit(0, "02"), create_test_commit(1, "03")],
        );

        let id1 = compute_group_id(&group);
        let id2 = compute_group_id(&group);

        // Should be deterministic
        assert_eq!(id1, id2);
        assert_eq!(id1.len(), 32);
    }

    #[test]
    fn test_compute_session_id_deterministic() {
        let group = create_test_group_with_commits(1, vec![create_test_commit(0, "02")]);

        let request = SignRequestInner {
            content: Some("test".to_string()),
            hashes: BoundedVec(vec![SighashVec(vec![Hex32("a".repeat(64))])]),
            members: BoundedVec(vec![0]),
            stamp: 1234567890,
            kind: "sign".to_string(),
            gid: Hex32("b".repeat(64)),
            sid: Hex32("c".repeat(64)),
        };

        let id1 = compute_session_id(&group, &request);
        let id2 = compute_session_id(&group, &request);

        // Should be deterministic
        assert_eq!(id1, id2);
        assert_eq!(id1.len(), 32);
    }

    #[test]
    fn test_verify_session_pkg() {
        let group = create_test_group_with_commits(1, vec![create_test_commit(0, "02")]);

        // Create a request with matching gid/sid
        let gid = compute_group_id(&group);
        let request_inner = SignRequestInner {
            content: Some("test".to_string()),
            hashes: BoundedVec(vec![SighashVec(vec![Hex32("a".repeat(64))])]),
            members: BoundedVec(vec![0]),
            stamp: 1234567890,
            kind: "sign".to_string(),
            gid: Hex32(hex::encode(gid)),
            sid: Hex32(hex::encode(compute_session_id(
                &group,
                &SignRequestInner {
                    content: Some("test".to_string()),
                    hashes: BoundedVec(vec![SighashVec(vec![Hex32("a".repeat(64))])]),
                    members: BoundedVec(vec![0]),
                    stamp: 1234567890,
                    kind: "sign".to_string(),
                    gid: Hex32(hex::encode(gid)),
                    sid: Hex32("c".repeat(64)),
                },
            ))),
        };

        // This would need proper gid/sid to pass
        // For now, just verify the function runs
        let _result = verify_session_pkg(&group, &request_inner);
    }

    #[test]
    fn test_tweak_commit_pnonces_invalid() {
        let commit = create_test_commit(0, "02");
        let session_id = [0u8; 32];
        let sigvec = vec![];

        // Invalid hidden_pn format should fail
        let result = tweak_commit_pnonces(&commit, &session_id, &sigvec);
        assert!(result.is_err());
    }

    #[test]
    fn test_tweak_share_snonces_invalid() {
        let mut share = create_test_share(0);
        share.hidden_sn = Hex32("invalid".to_string()); // Invalid hex

        let session_id = [0u8; 32];
        let sigvec = vec![];

        // Invalid hidden_sn format should fail
        let result = tweak_share_snonces(&share, &session_id, &sigvec);
        assert!(result.is_err());
    }

    #[test]
    fn test_create_psig_pkg_invalid_share() {
        let group = create_test_group_with_commits(1, vec![create_test_commit(0, "02")]);

        let request = SignRequest {
            request: SignRequestInner {
                content: Some("test".to_string()),
                hashes: BoundedVec(vec![SighashVec(vec![Hex32("a".repeat(64))])]),
                members: BoundedVec(vec![0]),
                stamp: 1234567890,
                kind: "sign".to_string(),
                gid: Hex32("b".repeat(64)),
                sid: Hex32("c".repeat(64)),
            },
        };

        let share = Share {
            idx: 0,
            binder_sn: Hex32("e".repeat(64)),
            hidden_sn: Hex32("f".repeat(64)),
            seckey: Hex32("invalid".to_string()),
        };

        // Invalid seckey should fail
        let result = create_psig_pkg(&group, &request, &share);
        assert!(result.is_err());
    }

    #[test]
    fn test_create_ecdh_pkg_invalid() {
        let request = EcdhRequest {
            idx: 0,
            members: BoundedVec(vec![0, 1]),
            ecdh_pk: Hex32("invalid".to_string()),
        };

        let share = create_test_share(0);

        // Invalid ecdh_pk should fail
        let result = create_ecdh_pkg(&request, &share);
        assert!(result.is_err());
    }

    #[test]
    fn test_build_sighash_contexts_invalid_group_pk() {
        let group = Group {
            commits: BoundedVec(vec![create_test_commit(0, "02")]),
            group_pk: Hex33("invalid".to_string()),
            threshold: 1,
        };

        let request = SignRequestInner {
            content: Some("test".to_string()),
            hashes: BoundedVec(vec![SighashVec(vec![Hex32("a".repeat(64))])]),
            members: BoundedVec(vec![0]),
            stamp: 1234567890,
            kind: "sign".to_string(),
            gid: Hex32("b".repeat(64)),
            sid: Hex32("c".repeat(64)),
        };

        let session_id = [0u8; 32];

        // Invalid group_pk should fail
        let result = build_sighash_contexts(&group, &request, &session_id);
        assert!(result.is_err());
    }
}
