/// End-to-end flow tests for the high-level frost API.
///
/// These tests exercise complete real-world usage scenarios without pinning
/// to specific byte values — they verify that the pieces compose correctly
/// and that outputs satisfy their cryptographic invariants.
use frost_taproot::{
    frost::{
        dealer::generate_dealer_package,
        dkg::{dkg_finalize, dkg_round1, dkg_round2},
        ecdh::{combine_ecdh_pkgs, create_ecdh_pkg},
        nonce::{derive_secret_nonce, generate_nonce_pair, to_member_nonce},
        signing::{
            combine_signatures, create_partial_sig_package, create_sign_session,
            verify_partial_sig_package,
        },
        types::MemberNonce,
    },
    shares::derive_shares_secret,
    types::SecretShare,
};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn s32(hex: &str) -> [u8; 32] {
    hex::decode(hex).unwrap().try_into().unwrap()
}

/// Run a complete signing round for `signers` (indices into `shares`) and
/// return the final signatures. Asserts partial sig verification passes for
/// each signer before combining.
fn sign_message(
    group: &frost_taproot::frost::types::GroupPackage,
    shares: &[frost_taproot::frost::types::SharePackage],
    signer_indices: &[usize],
    message: &[u8],
    tweaks: Vec<[u8; 32]>,
) -> Vec<frost_taproot::frost::types::Signature> {
    let signers: Vec<_> = signer_indices.iter().map(|&i| &shares[i]).collect();

    let nonce_pairs: Vec<_> = signers
        .iter()
        .map(|s| generate_nonce_pair(&s.seckey))
        .collect();

    let member_nonces: Vec<MemberNonce> = signers
        .iter()
        .zip(&nonce_pairs)
        .map(|(s, n)| to_member_nonce(n.clone(), s.idx))
        .collect();

    let secret_nonces: Vec<_> = signers
        .iter()
        .zip(&nonce_pairs)
        .map(|(s, n)| derive_secret_nonce(&s.seckey, &n.code))
        .collect();

    let session = create_sign_session(
        group,
        signers.iter().map(|s| s.idx).collect(),
        vec![(message.to_vec(), tweaks)],
        member_nonces,
    )
    .unwrap();

    let psigs: Vec<_> = signers
        .iter()
        .zip(&secret_nonces)
        .map(|(share, snonce)| {
            let pkg = create_partial_sig_package(&session, share, snonce).unwrap();
            let err = verify_partial_sig_package(&session, group, &pkg).unwrap();
            assert!(err.is_none(), "partial sig invalid: {:?}", err);
            pkg
        })
        .collect();

    combine_signatures(&session, group, &psigs).unwrap()
}

// ── Dealer flow ───────────────────────────────────────────────────────────────

/// Full dealer → sign → ECDH → secret recovery flow.
///
/// 1. Trusted dealer generates a 2-of-3 group.
/// 2. Every valid threshold subset can sign a message.
/// 3. Tweaked signing produces a different pubkey but still verifies.
/// 4. Threshold ECDH derives the same shared secret as a direct scalar mult.
/// 5. Any threshold subset of shares recovers the group secret.
#[test]
fn dealer_full_flow() {
    let secrets = [
        s32("0070ca75929ca1ec4cd70ac34f46079bdfdd87f9d0c0bf4275f3882f7b462d0f"),
        s32("0e0376a7180253cdb8b6020bff0eda529760da65e715663e2152e4be2fc7b443"),
    ];
    let pkg = generate_dealer_package(2, 3, &secrets).unwrap();
    let group = &pkg.group;
    let shares = &pkg.shares;

    assert_eq!(group.threshold, 2);
    assert_eq!(shares.len(), 3);
    for m in &group.members {
        assert_eq!(m.identity_pk, None);
    }

    // ── Signing: all three 2-of-3 subsets ────────────────────────────────────

    let message = b"hello from the dealer flow";

    for subset in [[0, 1], [0, 2], [1, 2]] {
        let sigs = sign_message(group, shares, &subset, message, vec![]);
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].message, message);
        assert_eq!(
            sigs[0].pubkey, group.group_pk,
            "untweaked sig pubkey should equal group_pk"
        );
    }

    // ── Signing: with tweaks ──────────────────────────────────────────────────

    let tweak = s32("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    let tweaked_sigs = sign_message(group, shares, &[0, 1], message, vec![tweak]);
    assert_eq!(tweaked_sigs.len(), 1);
    assert_ne!(
        tweaked_sigs[0].pubkey, group.group_pk,
        "tweaked sig pubkey should differ from group_pk"
    );

    // ── Signing: multiple messages in one session ─────────────────────────────

    let nonce_pairs: Vec<_> = shares[..2]
        .iter()
        .map(|s| generate_nonce_pair(&s.seckey))
        .collect();
    let member_nonces: Vec<MemberNonce> = shares[..2]
        .iter()
        .zip(&nonce_pairs)
        .map(|(s, n)| to_member_nonce(n.clone(), s.idx))
        .collect();
    let secret_nonces: Vec<_> = shares[..2]
        .iter()
        .zip(&nonce_pairs)
        .map(|(s, n)| derive_secret_nonce(&s.seckey, &n.code))
        .collect();

    let messages = vec![
        (b"first message".to_vec(), vec![]),
        (b"second message".to_vec(), vec![]),
    ];
    let session = create_sign_session(group, vec![1, 2], messages.clone(), member_nonces).unwrap();
    let psigs: Vec<_> = shares[..2]
        .iter()
        .zip(&secret_nonces)
        .map(|(s, sn)| create_partial_sig_package(&session, s, sn).unwrap())
        .collect();
    let multi_sigs = combine_signatures(&session, group, &psigs).unwrap();
    assert_eq!(multi_sigs.len(), 2);
    assert_eq!(multi_sigs[0].message, messages[0].0);
    assert_eq!(multi_sigs[1].message, messages[1].0);

    // ── ECDH ─────────────────────────────────────────────────────────────────

    // Generate an external keypair to derive a shared secret with.
    let ext_seckey = s32("1111111111111111111111111111111111111111111111111111111111111111");
    let ext_pubkey = frost_taproot::helpers::get_pubkey(&ext_seckey);

    // Use members 1 and 3 as the quorum.
    let ecdh_members = [1u32, 3u32];
    let ecdh1 = create_ecdh_pkg(&ecdh_members, &ext_pubkey, &shares[0]).unwrap();
    let ecdh3 = create_ecdh_pkg(&ecdh_members, &ext_pubkey, &shares[2]).unwrap();
    let frost_shared = combine_ecdh_pkgs(&[ecdh1, ecdh3], &ext_pubkey).unwrap();

    // The shared secret must equal ext_pubkey * group_secret = group_pk * ext_seckey.
    // Verify by computing it the direct way: tweak_pubkey(ext_pubkey, group_secret).
    let group_secret = derive_shares_secret(&[
        SecretShare {
            idx: shares[0].idx,
            seckey: shares[0].seckey,
        },
        SecretShare {
            idx: shares[2].idx,
            seckey: shares[2].seckey,
        },
    ])
    .unwrap();
    let direct_shared = frost_taproot::helpers::tweak_pubkey(&ext_pubkey, &group_secret).unwrap();
    assert_eq!(
        frost_shared, direct_shared,
        "FROST ECDH shared secret must match direct computation"
    );

    // ── Secret recovery ───────────────────────────────────────────────────────

    // Any threshold subset recovers the same secret.
    let secret_12 = derive_shares_secret(&[
        SecretShare {
            idx: shares[0].idx,
            seckey: shares[0].seckey,
        },
        SecretShare {
            idx: shares[1].idx,
            seckey: shares[1].seckey,
        },
    ])
    .unwrap();
    let secret_13 = derive_shares_secret(&[
        SecretShare {
            idx: shares[0].idx,
            seckey: shares[0].seckey,
        },
        SecretShare {
            idx: shares[2].idx,
            seckey: shares[2].seckey,
        },
    ])
    .unwrap();
    let secret_23 = derive_shares_secret(&[
        SecretShare {
            idx: shares[1].idx,
            seckey: shares[1].seckey,
        },
        SecretShare {
            idx: shares[2].idx,
            seckey: shares[2].seckey,
        },
    ])
    .unwrap();

    assert_eq!(
        secret_12, secret_13,
        "all subsets must recover the same secret"
    );
    assert_eq!(secret_13, secret_23);

    // The recovered secret's public key must equal the group public key.
    let recovered_pk = frost_taproot::helpers::get_pubkey(&secret_12);
    assert_eq!(
        recovered_pk, group.group_pk,
        "recovered secret * G must equal group_pk"
    );
}

// ── DKG flow ──────────────────────────────────────────────────────────────────

/// Full DKG → sign → ECDH → secret recovery flow.
///
/// 1. Three participants run Pedersen DKG to produce a shared group key
///    without any trusted dealer.
/// 2. All participants agree on the same group public key.
/// 3. Member pubkeys are share pubkeys (usable for partial sig verification).
/// 4. Member identity_pks are the per-participant first VSS commits.
/// 5. Every valid threshold subset can sign a message.
/// 6. Tweaked signing works correctly.
/// 7. Threshold ECDH derives the same shared secret as a direct scalar mult.
/// 8. Any threshold subset of aggregate shares recovers the group secret.
#[test]
fn dkg_full_flow() {
    // Three participants, threshold 2, fully deterministic seeds.
    let participant_seeds: Vec<Vec<[u8; 32]>> = vec![
        vec![
            s32("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            s32("1111111111111111111111111111111111111111111111111111111111111111"),
        ],
        vec![
            s32("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
            s32("2222222222222222222222222222222222222222222222222222222222222222"),
        ],
        vec![
            s32("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"),
            s32("3333333333333333333333333333333333333333333333333333333333333333"),
        ],
    ];

    // ── Round 1 ───────────────────────────────────────────────────────────────

    let round1: Vec<_> = (1u32..=3)
        .zip(&participant_seeds)
        .map(|(idx, seeds)| dkg_round1(idx, 2, seeds))
        .collect();

    let all_commits: Vec<_> = round1.iter().map(|(_, c)| c.clone()).collect();

    // ── Round 2 ───────────────────────────────────────────────────────────────

    let all_shares: Vec<_> = round1
        .iter()
        .flat_map(|(coeffs, commit)| {
            (1u32..=3).map(move |recipient| dkg_round2(commit.idx, coeffs, recipient).unwrap())
        })
        .collect();

    // ── Finalize ──────────────────────────────────────────────────────────────

    let outputs: Vec<_> = (0..3)
        .map(|i| {
            let my_idx = (i + 1) as u32;
            let (my_coeffs, _) = &round1[i];
            let received: Vec<_> = all_shares
                .iter()
                .filter(|s| s.recipient_idx == my_idx && s.sender_idx != my_idx)
                .cloned()
                .collect();
            dkg_finalize(my_idx, my_coeffs, &received, &all_commits, 2).unwrap()
        })
        .collect();

    // All participants must agree on the same group public key.
    let group_pk = outputs[0].group.group_pk;
    for output in &outputs {
        assert_eq!(
            output.group.group_pk, group_pk,
            "all participants must agree on group_pk"
        );
        assert_eq!(output.group.threshold, 2);
    }

    // Member pubkeys must be share pubkeys (seckey * G), not identity keys.
    for output in &outputs {
        let expected_pk = frost_taproot::helpers::get_pubkey(&output.share.seckey);
        let member = output
            .group
            .members
            .iter()
            .find(|m| m.idx == output.share.idx)
            .unwrap();
        assert_eq!(
            member.pubkey, expected_pk,
            "member.pubkey must equal share pubkey for participant {}",
            output.share.idx
        );
    }

    // identity_pk must be set and equal to each participant's first VSS commit.
    for (i, output) in outputs.iter().enumerate() {
        let (_, commit) = &round1[i];
        let member = output
            .group
            .members
            .iter()
            .find(|m| m.idx == commit.idx)
            .unwrap();
        assert_eq!(
            member.identity_pk,
            Some(commit.vss_commits[0]),
            "identity_pk must equal first VSS commit for participant {}",
            commit.idx
        );
    }

    // ── Signing: all three 2-of-3 subsets ────────────────────────────────────

    let message = b"hello from the dkg flow";
    let group = &outputs[0].group;
    let shares: Vec<_> = outputs.iter().map(|o| o.share.clone()).collect();

    for subset in [[0usize, 1], [0, 2], [1, 2]] {
        let sigs = sign_message(group, &shares, &subset, message, vec![]);
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].message, message);
        assert_eq!(
            sigs[0].pubkey, group_pk,
            "untweaked sig pubkey should equal group_pk"
        );
    }

    // ── Signing: with tweaks ──────────────────────────────────────────────────

    let tweak = s32("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    let tweaked_sigs = sign_message(group, &shares, &[0, 1], message, vec![tweak]);
    assert_eq!(tweaked_sigs.len(), 1);
    assert_ne!(
        tweaked_sigs[0].pubkey, group_pk,
        "tweaked sig pubkey should differ from group_pk"
    );

    // ── ECDH ─────────────────────────────────────────────────────────────────

    let ext_seckey = s32("1111111111111111111111111111111111111111111111111111111111111111");
    let ext_pubkey = frost_taproot::helpers::get_pubkey(&ext_seckey);

    let ecdh_members = [1u32, 3u32];
    let ecdh1 = create_ecdh_pkg(&ecdh_members, &ext_pubkey, &shares[0]).unwrap();
    let ecdh3 = create_ecdh_pkg(&ecdh_members, &ext_pubkey, &shares[2]).unwrap();
    let frost_shared = combine_ecdh_pkgs(&[ecdh1, ecdh3], &ext_pubkey).unwrap();

    // Recover the group secret to verify ECDH directly.
    let group_secret = derive_shares_secret(&[
        SecretShare {
            idx: shares[0].idx,
            seckey: shares[0].seckey,
        },
        SecretShare {
            idx: shares[2].idx,
            seckey: shares[2].seckey,
        },
    ])
    .unwrap();
    let direct_shared = frost_taproot::helpers::tweak_pubkey(&ext_pubkey, &group_secret).unwrap();
    assert_eq!(
        frost_shared, direct_shared,
        "FROST ECDH shared secret must match direct computation"
    );

    // ── Secret recovery ───────────────────────────────────────────────────────

    let secret_12 = derive_shares_secret(&[
        SecretShare {
            idx: shares[0].idx,
            seckey: shares[0].seckey,
        },
        SecretShare {
            idx: shares[1].idx,
            seckey: shares[1].seckey,
        },
    ])
    .unwrap();
    let secret_13 = derive_shares_secret(&[
        SecretShare {
            idx: shares[0].idx,
            seckey: shares[0].seckey,
        },
        SecretShare {
            idx: shares[2].idx,
            seckey: shares[2].seckey,
        },
    ])
    .unwrap();
    let secret_23 = derive_shares_secret(&[
        SecretShare {
            idx: shares[1].idx,
            seckey: shares[1].seckey,
        },
        SecretShare {
            idx: shares[2].idx,
            seckey: shares[2].seckey,
        },
    ])
    .unwrap();

    assert_eq!(
        secret_12, secret_13,
        "all subsets must recover the same secret"
    );
    assert_eq!(secret_13, secret_23);

    // The recovered secret's public key must equal the group public key.
    let recovered_pk = frost_taproot::helpers::get_pubkey(&secret_12);
    assert_eq!(
        recovered_pk, group_pk,
        "recovered secret * G must equal group_pk"
    );

    // The DKG group secret is the sum of all participants' constant terms.
    // Verify: secret = s1_const + s2_const + s3_const (mod N).
    use frost_taproot::ecc::util::{scalar_from_bytes, scalar_to_bytes};
    let sum = participant_seeds
        .iter()
        .fold(k256::Scalar::ZERO, |acc, seeds| {
            acc + scalar_from_bytes(&seeds[0])
        });
    assert_eq!(
        secret_12,
        scalar_to_bytes(&sum),
        "DKG secret must equal sum of participants' constant terms"
    );
}
