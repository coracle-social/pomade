//! Regression test for the DKG rogue-key attack.
//!
//! Original bug: `dkg_finalize` set the group key to the unauthenticated sum of
//! every participant's `vss_commits[0]`. With no proof of possession and no
//! commit-then-reveal round, a participant broadcasting last could choose its
//! commitments as a function of everyone else's — `f = w − S·L₀`, where `S·G` is
//! the sum of the honest constant commitments — cancelling the honest
//! contributions so the group key became `l·G` for an `l` it knew, while every
//! honest share still verified. A single such party controlled the key when
//! `n == t`; a sub-threshold coalition controlled it even against an honest
//! majority.
//!
//! Fix: each Round-1 commitment now carries a Schnorr proof of possession of the
//! discrete log of `vss_commits[0]`, bound to the participant index, and
//! `dkg_finalize` verifies every PoP before folding any commitment into the
//! group key. The crafted cancelling commitment has unknown discrete log, so no
//! valid PoP exists for it — the attacker's strongest move is to attach a
//! genuine PoP for a *different* point it controls, which fails because the PoP
//! is bound to the (index, commitment) it is presented with.

use frost_taproot::{
    ecc::{
        group::{scalar_base_multi, scalar_multi, serialize_element},
        util::{lift_x, scalar_from_bytes, scalar_invert, scalar_to_bytes},
    },
    frost::{
        dealer::is_group_member,
        dkg::{dkg_finalize, dkg_round1, dkg_round2, verify_dkg_pop, verify_dkg_share},
        types::{DkgCommitPackage, DkgPop, DkgSharePackage, SharePackage},
    },
    helpers::get_pubkey,
    poly::{evaluate_x, index_to_scalar},
    shares::verify_share,
    types::SecretShare,
};
use k256::{ProjectivePoint, Scalar};

fn s32(hex: &str) -> [u8; 32] {
    hex::decode(hex).unwrap().try_into().unwrap()
}

fn eval(coeffs: &[Scalar], i: u32) -> Scalar {
    evaluate_x(coeffs, index_to_scalar(i)).unwrap()
}

/// Monic coefficients (low→high) of `∏(z − r)`.
fn poly_from_roots(roots: &[u32]) -> Vec<Scalar> {
    let mut c = vec![Scalar::ONE];
    for &r in roots {
        let r = index_to_scalar(r);
        let mut next = vec![Scalar::ZERO; c.len() + 1];
        for i in 0..c.len() {
            next[i] -= r * c[i];
            next[i + 1] += c[i];
        }
        c = next;
    }
    c
}

/// Lagrange basis for node 0 over `{0} ∪ honest`: `L₀(0)=1`, `L₀(j)=0 ∀ honest j`.
fn lagrange_node0(honest: &[u32]) -> Vec<Scalar> {
    let num = poly_from_roots(honest);
    let denom = honest
        .iter()
        .fold(Scalar::ONE, |a, &j| a * (Scalar::ZERO - index_to_scalar(j)));
    let inv = scalar_invert(&denom).unwrap();
    num.iter().map(|&c| c * inv).collect()
}

/// The malicious "canceller". It crafts a commitment whose constant term is
/// `w0·G − S·G` (a point whose discrete log it does not know), then attaches its
/// strongest available proof: a *genuine* PoP for `w0·G` (a point it controls),
/// obtained from the real `dkg_round1` API. That PoP is bound to a different
/// commitment, so it cannot authenticate the crafted one.
fn malicious_canceller(
    idx: u32,
    threshold: usize,
    honest_commits: &[&DkgCommitPackage],
    honest_indices: &[u32],
    w: &[Scalar],
) -> (DkgCommitPackage, Vec<DkgSharePackage>) {
    let s_g = honest_commits
        .iter()
        .fold(ProjectivePoint::IDENTITY, |acc, c| {
            acc + lift_x(&c.vss_commits[0]).unwrap()
        });
    let l0 = lagrange_node0(honest_indices);
    let vss_commits: Vec<[u8; 33]> = (0..w.len())
        .map(|k| {
            let l0k = l0.get(k).copied().unwrap_or(Scalar::ZERO);
            serialize_element(&(scalar_base_multi(&w[k]) - scalar_multi(&s_g, &l0k)))
        })
        .collect();

    // Strongest forgery the attacker can mount: a real proof for `w0·G`, which it
    // does control, generated through the honest API with the same index.
    let w_bytes: Vec<[u8; 32]> = w.iter().map(scalar_to_bytes).collect();
    let (_, decoy) = dkg_round1(idx, threshold, &w_bytes);
    let forged_pop: DkgPop = decoy.pop;

    let shares = honest_indices
        .iter()
        .map(|&j| DkgSharePackage {
            sender_idx: idx,
            recipient_idx: j,
            seckey: scalar_to_bytes(&eval(w, j)),
        })
        .collect();
    (
        DkgCommitPackage {
            idx,
            vss_commits,
            pop: forged_pop,
        },
        shares,
    )
}

#[test]
fn rogue_canceller_rejected_2_of_2() {
    // n = t = 2: one honest party (1), one malicious (2).
    let t = 2;
    let l = s32("00000000000000000000000000000000000000000000000000000000deadbeef");
    let w = vec![
        scalar_from_bytes(&l),
        scalar_from_bytes(&s32(
            "0000000000000000000000000000000000000000000000000000000000c0ffee",
        )),
    ];

    let (coeffs1, commit1) = dkg_round1(1, t, &[s32(&"aa".repeat(32))]);
    let (commit2, shares2) = malicious_canceller(2, t, &[&commit1], &[1], &w);
    let all = vec![commit1, commit2.clone()];

    // The crafted commitment's share still passes VSS — that was never the
    // defense. The PoP is what fails.
    assert!(verify_dkg_share(&shares2[0], &commit2, t).unwrap());
    assert!(
        !verify_dkg_pop(2, &commit2.vss_commits[0], &commit2.pop).unwrap(),
        "no valid PoP exists for the crafted commitment"
    );

    let result = dkg_finalize(1, &coeffs1, &shares2, &all, t);
    assert!(
        result.is_err(),
        "finalize must reject the rogue commitment instead of folding l·G into the group key"
    );
}

#[test]
fn rogue_canceller_rejected_4_of_5_honest_majority() {
    // n = 5, t = 4: honest {1,2,3} (a 3/5 majority, below threshold 4),
    // malicious 4 (canceller) + 5 (filler).
    let t = 4;
    let honest = [1u32, 2, 3];
    let l = s32("00000000000000000000000000000000000000000000000000000000c0ded00d");
    let k5 = s32("0000000000000000000000000000000000000000000000000000000000000045");
    let w = vec![
        scalar_from_bytes(&l) - scalar_from_bytes(&k5),
        scalar_from_bytes(&s32(&"11".repeat(32))),
        scalar_from_bytes(&s32(&"22".repeat(32))),
        scalar_from_bytes(&s32(&"33".repeat(32))),
    ];

    let (h_coeffs, h_commits): (Vec<_>, Vec<_>) =
        honest.iter().map(|&i| dkg_round1(i, t, &[])).unzip();
    let refs: Vec<&DkgCommitPackage> = h_commits.iter().collect();
    let (commit4, c4) = malicious_canceller(4, t, &refs, &honest, &w);
    let (coeffs5, commit5) = dkg_round1(5, t, &[k5]);

    let all: Vec<DkgCommitPackage> = h_commits
        .iter()
        .cloned()
        .chain([commit4, commit5])
        .collect();

    // Every honest finalizer must reject — the attack cannot complete for anyone.
    for (slot, &me) in honest.iter().enumerate() {
        let mut received = Vec::new();
        for (s, &sender) in honest.iter().enumerate() {
            if sender != me {
                received.push(dkg_round2(sender, &h_coeffs[s], me).unwrap());
            }
        }
        received.push(c4.iter().find(|s| s.recipient_idx == me).unwrap().clone());
        received.push(dkg_round2(5, &coeffs5, me).unwrap());

        let result = dkg_finalize(me, &h_coeffs[slot], &received, &all, t);
        assert!(
            result.is_err(),
            "honest party {me} must reject the rogue DKG instead of accepting l·G"
        );
    }
}

#[test]
fn honest_dkg_still_finalizes_and_pop_roundtrips() {
    // The fix must not break a legitimate DKG: an honest 2-of-2 completes, the
    // shares verify, and the PoPs verify (true) / reject a tampered PoP (false).
    let t = 2;
    let (coeffs1, commit1) = dkg_round1(1, t, &[s32(&"aa".repeat(32))]);
    let (coeffs2, commit2) = dkg_round1(2, t, &[s32(&"bb".repeat(32))]);
    let all = vec![commit1.clone(), commit2.clone()];

    // Honest PoPs verify.
    assert!(verify_dkg_pop(1, &commit1.vss_commits[0], &commit1.pop).unwrap());
    assert!(verify_dkg_pop(2, &commit2.vss_commits[0], &commit2.pop).unwrap());

    // A PoP presented under the wrong index does not verify (binding).
    assert!(!verify_dkg_pop(2, &commit1.vss_commits[0], &commit1.pop).unwrap());

    // A tampered PoP response does not verify.
    let mut bad = commit1.pop.clone();
    bad.z[0] ^= 0xff;
    assert!(!verify_dkg_pop(1, &commit1.vss_commits[0], &bad).unwrap());

    let recv = |me: u32, sender: u32, sender_coeffs: &[[u8; 32]]| {
        vec![dkg_round2(sender, sender_coeffs, me).unwrap()]
    };
    let out1 = dkg_finalize(1, &coeffs1, &recv(1, 2, &coeffs2), &all, t).unwrap();
    let out2 = dkg_finalize(2, &coeffs2, &recv(2, 1, &coeffs1), &all, t).unwrap();

    assert_eq!(
        out1.group.group_pk, out2.group.group_pk,
        "honest parties agree"
    );

    for (out, idx) in [(&out1, 1u32), (&out2, 2u32)] {
        let share = SharePackage {
            idx,
            seckey: out.share.seckey,
        };
        assert!(is_group_member(&out.group, &share));
        let secret = SecretShare {
            idx,
            seckey: out.share.seckey,
        };
        assert!(verify_share(&out.vss_commits, &secret, t).unwrap());
    }

    // Sanity: the group key is the honest sum of constant terms, not attacker-chosen.
    let expected = serialize_element(
        &(lift_x(&commit1.vss_commits[0]).unwrap() + lift_x(&commit2.vss_commits[0]).unwrap()),
    );
    assert_eq!(out1.group.group_pk, expected);
    // And it is decidedly not under solo control via some `l`.
    let l = s32("00000000000000000000000000000000000000000000000000000000deadbeef");
    assert_ne!(out1.group.group_pk, get_pubkey(&l));
}
