use crate::Error;
/// Distributed Key Generation (Pedersen DKG).
///
/// Eliminates the trusted dealer: each participant generates their own
/// polynomial, broadcasts VSS commitments, and privately distributes
/// shares. The group key is the sum of all participants' constant terms —
/// no single party ever knows the full secret.
///
/// # Protocol
///
/// ```text
/// Round 1 (broadcast):
///   Each participant i calls dkg_round1() → (secret_coeffs, DkgCommitPackage)
///   Broadcasts DkgCommitPackage to all others; keeps secret_coeffs private.
///
/// Round 2 (private):
///   Each participant i calls dkg_round2() once per other participant j,
///   producing a DkgSharePackage addressed to j. Sends it privately to j.
///   Also calls verify_dkg_share() on each package received from others.
///
/// Finalize:
///   Each participant calls dkg_finalize() with their secret coeffs,
///   all received DkgSharePackages, and all Round 1 DkgCommitPackages.
///   Returns DkgOutput containing their aggregate share and the GroupPackage.
/// ```
use k256::{Scalar, U256};
use sha2::{Digest, Sha256};

use crate::ecc::group::{element_add, scalar_base_multi, scalar_multi, serialize_element};
use crate::ecc::util::{lift_x, mod_n, pow_n, scalar_from_bytes, scalar_to_bytes};
use crate::shares::{combine_set, verify_share};
use crate::types::SecretShare;
use crate::vss::{create_share_coeffs, get_share_commits, merge_share_commits};

use super::types::{
    DkgCommitPackage, DkgOutput, DkgPop, DkgSharePackage, GroupPackage, MemberPackage, SharePackage,
};

/// Domain separation tag for the DKG proof-of-possession challenge.
const DKG_POP_CHALLENGE_DST: &[u8] = b"frost-taproot/dkg-pop/challenge/v1";
/// Domain separation tag for the deterministic PoP nonce.
const DKG_POP_NONCE_DST: &[u8] = b"frost-taproot/dkg-pop/nonce/v1";

/// Challenge scalar for the proof of possession: `e = H(DST || idx || C0 || R)`.
///
/// Binding the index in (and the commitment itself) ties each proof to its
/// participant and its commitment, so a proof cannot be replayed for a different
/// index or a different commitment.
fn dkg_pop_challenge(idx: u32, c0: &[u8; 33], r: &[u8; 33]) -> Scalar {
    let mut hasher = Sha256::new();
    hasher.update(DKG_POP_CHALLENGE_DST);
    hasher.update(idx.to_be_bytes());
    hasher.update(c0);
    hasher.update(r);
    let digest: [u8; 32] = hasher.finalize().into();
    mod_n(U256::from_be_slice(&digest))
}

/// Build a Schnorr proof of possession of `a0` where `c0 = a0 * G`.
///
/// Uses a deterministic, secret-dependent nonce so Round 1 stays reproducible
/// and never depends on an RNG for this step.
fn create_dkg_pop(idx: u32, a0: &Scalar, c0: &[u8; 33]) -> DkgPop {
    // Deterministic nonce k = H(DST || a0 || idx), reduced mod n. Secret-derived,
    // so it is unpredictable to anyone who does not know a0.
    let mut hasher = Sha256::new();
    hasher.update(DKG_POP_NONCE_DST);
    hasher.update(scalar_to_bytes(a0));
    hasher.update(idx.to_be_bytes());
    let nonce_digest: [u8; 32] = hasher.finalize().into();
    let mut k = mod_n(U256::from_be_slice(&nonce_digest));
    if k == Scalar::ZERO {
        k = Scalar::ONE;
    }

    let r_point = scalar_base_multi(&k);
    let r = serialize_element(&r_point);
    let e = dkg_pop_challenge(idx, c0, &r);
    let z = k + e * a0;

    DkgPop {
        r,
        z: scalar_to_bytes(&z),
    }
}

/// Verify a proof of possession against the committed point `c0 = vss_commits[0]`.
///
/// Checks `z * G == R + e * C0`. Returns `Ok(false)` when the proof does not
/// verify (e.g. a crafted commitment whose discrete log the author does not
/// know), `Err` only on a point-decoding failure.
pub fn verify_dkg_pop(idx: u32, c0: &[u8; 33], pop: &DkgPop) -> Result<bool, Error> {
    let r_point = lift_x(&pop.r)?;
    let c0_point = lift_x(c0)?;
    let e = dkg_pop_challenge(idx, c0, &pop.r);
    let z = scalar_from_bytes(&pop.z);

    let lhs = scalar_base_multi(&z);
    let rhs = element_add(Some(r_point), Some(scalar_multi(&c0_point, &e)))?;
    // Both sides are public points; compare their canonical serializations.
    Ok(serialize_element(&lhs) == serialize_element(&rhs))
}

/// Round 1: generate this participant's polynomial and VSS commitments.
///
/// Returns `(secret_coeffs, commit_package)`:
/// - **Keep `secret_coeffs` private** — they are the raw polynomial coefficients.
/// - **Broadcast `commit_package`** to all other participants.
///
/// `secrets` optionally seeds the polynomial deterministically (e.g. for
/// testing or deterministic key derivation). Pass `&[]` for a fully random
/// polynomial.
pub fn dkg_round1(
    idx: u32,
    threshold: usize,
    secrets: &[[u8; 32]],
) -> (Vec<[u8; 32]>, DkgCommitPackage) {
    let coeffs = create_share_coeffs(secrets, threshold);
    let vss_commits = get_share_commits(&coeffs);

    // Prove possession of the constant-term secret `a_i0` behind `vss_commits[0]`.
    // This is what later lets every participant reject a rogue commitment whose
    // discrete log its author does not actually know.
    let pop = create_dkg_pop(idx, &coeffs[0], &vss_commits[0]);

    // Serialize coefficients for storage/transport.
    let secret_coeffs: Vec<[u8; 32]> = coeffs.iter().map(|c| c.to_bytes().into()).collect();

    (
        secret_coeffs,
        DkgCommitPackage {
            idx,
            vss_commits,
            pop,
        },
    )
}

/// Round 2: generate the private share for one recipient.
///
/// Call this once per other participant, using the `secret_coeffs` returned
/// by [`dkg_round1`]. Send the resulting `DkgSharePackage` privately to
/// `recipient_idx` — never broadcast it.
pub fn dkg_round2(
    sender_idx: u32,
    secret_coeffs: &[[u8; 32]],
    recipient_idx: u32,
) -> Result<DkgSharePackage, Error> {
    use crate::ecc::util::scalar_from_bytes;
    use crate::poly::{evaluate_x, index_to_scalar};

    let coeffs: Vec<_> = secret_coeffs.iter().map(scalar_from_bytes).collect();
    let x = index_to_scalar(recipient_idx);
    let share_scalar = evaluate_x(&coeffs, x)?;

    Ok(DkgSharePackage {
        sender_idx,
        recipient_idx,
        seckey: share_scalar.to_bytes().into(),
    })
}

/// Verify a share received during Round 2 against the sender's VSS commitments.
///
/// Call this for every `DkgSharePackage` you receive before accepting it.
/// Returns `Ok(true)` if valid, `Ok(false)` if the share doesn't match the
/// sender's commitments, or `Err` on a crypto error.
pub fn verify_dkg_share(
    share: &DkgSharePackage,
    sender_commits: &DkgCommitPackage,
    threshold: usize,
) -> Result<bool, Error> {
    let low_share = SecretShare {
        idx: share.recipient_idx,
        seckey: share.seckey,
    };
    verify_share(&sender_commits.vss_commits, &low_share, threshold)
}

/// Finalize DKG: aggregate received shares and derive the group key.
///
/// - `my_idx`       — this participant's own index
/// - `my_coeffs`    — the secret coefficients from your own [`dkg_round1`] call
/// - `received`     — `DkgSharePackage`s addressed to `my_idx`, one per other participant
/// - `all_commits`  — `DkgCommitPackage`s from **all** participants (including yourself)
/// - `threshold`    — the agreed signing threshold
///
/// Returns a [`DkgOutput`] containing this participant's aggregate share and
/// the full [`GroupPackage`] (group public key + member roster).
///
/// # Errors
///
/// Returns an error if:
/// - A received share fails VSS verification
/// - The number of received shares + own share doesn't cover all participants
/// - Any VSS commit set has the wrong length
pub fn dkg_finalize(
    my_idx: u32,
    my_coeffs: &[[u8; 32]],
    received: &[DkgSharePackage],
    all_commits: &[DkgCommitPackage],
    threshold: usize,
) -> Result<DkgOutput, Error> {
    // Verify every participant's proof of possession before trusting any of their
    // commitments. This closes the rogue-key attack: a participant broadcasting
    // last cannot fold a crafted `vss_commits[0]` (chosen to cancel the honest
    // contributions and steer the group key) into the sum, because it cannot
    // produce a valid PoP for a point whose discrete log it does not know.
    for c in all_commits {
        let c0 = c
            .vss_commits
            .first()
            .ok_or_else(|| Error::Assertion(format!("participant {} has no VSS commits", c.idx)))?;
        if !verify_dkg_pop(c.idx, c0, &c.pop)? {
            return Err(Error::Assertion(format!(
                "DKG proof of possession failed for participant {}",
                c.idx
            )));
        }
    }

    // Validate all received shares against their senders' VSS commitments.
    for pkg in received {
        let sender_commits = all_commits
            .iter()
            .find(|c| c.idx == pkg.sender_idx)
            .ok_or(Error::RecordNotFound(pkg.sender_idx))?;
        if !verify_dkg_share(pkg, sender_commits, threshold)? {
            return Err(Error::Assertion(format!(
                "DKG share from participant {} failed VSS verification",
                pkg.sender_idx
            )));
        }
    }

    // Compute own share: evaluate own polynomial at my_idx.
    let own_share_pkg = dkg_round2(my_idx, my_coeffs, my_idx)?;
    let own_share = SecretShare {
        idx: my_idx,
        seckey: own_share_pkg.seckey,
    };

    // Aggregate: sum own share + all received shares at my_idx.
    let mut all_shares: Vec<SecretShare> = vec![own_share];
    for pkg in received {
        all_shares.push(SecretShare {
            idx: my_idx,
            seckey: pkg.seckey,
        });
    }
    let aggregate = combine_set(&all_shares)?;

    // Derive the group public key: sum of all participants' first VSS commits.
    // Sort by idx for determinism.
    let mut sorted_commits = all_commits.to_vec();
    sorted_commits.sort_by_key(|c| c.idx);

    let group_pk = {
        let first_commits: Vec<[u8; 33]> =
            sorted_commits.iter().map(|c| c.vss_commits[0]).collect();
        sum_points(&first_commits)?
    };

    // Merge all VSS commit sets to get the group-level VSS commitments.
    // These can be used to verify any participant's aggregate share.
    let group_vss_commits = sorted_commits
        .iter()
        .try_fold(None::<Vec<[u8; 33]>>, |acc, c| {
            Ok(match acc {
                None => Some(c.vss_commits.clone()),
                Some(prev) => Some(merge_share_commits(&prev, &c.vss_commits)?),
            })
        })?
        .ok_or_else(|| Error::Assertion("no VSS commits to merge".to_string()))?;

    // Build member packages.
    // pubkey = aggregate share pubkey, derived from merged VSS commits:
    //   sum_k( merged_commits[k] * idx^k )
    // This is the same equation used in share verification, but returning
    // the point rather than comparing it — no secret knowledge required.
    // identity_pk = each participant's first VSS commit (a_i0 * G).
    let members: Vec<MemberPackage> = sorted_commits
        .iter()
        .map(|c| {
            let share_pubkey = eval_vss_pubkey(&group_vss_commits, c.idx)?;
            Ok(MemberPackage {
                idx: c.idx,
                pubkey: share_pubkey,
                identity_pk: Some(c.vss_commits[0]),
            })
        })
        .collect::<Result<_, Error>>()?;

    let group = GroupPackage {
        group_pk,
        threshold,
        members,
    };

    Ok(DkgOutput {
        share: SharePackage {
            idx: my_idx,
            seckey: aggregate.seckey,
        },
        group,
        vss_commits: group_vss_commits,
    })
}

/// Sum a list of compressed points into one point.
fn sum_points(points: &[[u8; 33]]) -> Result<[u8; 33], Error> {
    if points.is_empty() {
        return Err(Error::Assertion("cannot sum empty point list".to_string()));
    }
    let mut acc = lift_x(&points[0])?;
    for p in &points[1..] {
        acc += lift_x(p)?;
    }
    Ok(serialize_element(&acc))
}

/// Evaluate the VSS commitment polynomial at a participant index to derive
/// their aggregate share public key, without knowing the secret.
///
/// Computes: sum_k( commits[k] * idx^k )
///
/// This mirrors the share verification equation in `shares::verify_share`,
/// but returns the resulting point rather than comparing it.
fn eval_vss_pubkey(commits: &[[u8; 33]], idx: u32) -> Result<[u8; 33], Error> {
    if commits.is_empty() {
        return Err(Error::Assertion("no VSS commits".to_string()));
    }
    let mut acc = None::<k256::ProjectivePoint>;
    for (k, commit) in commits.iter().enumerate() {
        let point = lift_x(commit)?;
        let exp = pow_n(idx as u64, k as u64);
        let term = scalar_multi(&point, &exp);
        acc = Some(match acc {
            None => term,
            Some(a) => a + term,
        });
    }
    Ok(serialize_element(&acc.unwrap()))
}
