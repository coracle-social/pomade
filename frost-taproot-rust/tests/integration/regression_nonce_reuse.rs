//! Regression test for the nonce-reuse share-recovery vulnerability.
//!
//! Original bug: a `SignSession` carried a list of messages but only one nonce
//! per member, and `create_partial_sig_package` signed every message with that
//! single reused nonce. Three messages then formed a solvable 3-unknown linear
//! system `(seckey, hidden_sn, binder_sn)`, letting a co-signer or coordinator
//! recover the victim's secret share from its own partial signatures.
//!
//! Fix: a session is structurally single-message — `create_sign_session` rejects
//! any message list whose length isn't exactly 1, so one fresh nonce can never
//! sign more than one message. (A deterministic per-message tweak of one base
//! nonce does NOT fix this: the tweak is public, so the attacker subtracts it
//! out and the 3-unknown system still solves. Single-use is the real fix.)

use frost_taproot::frost::{
    dealer::generate_dealer_package,
    nonce::{derive_secret_nonce, generate_nonce_pair, to_member_nonce},
    signing::{combine_signatures, create_partial_sig_package, create_sign_session},
    types::MemberNonce,
};

fn s32(hex: &str) -> [u8; 32] {
    hex::decode(hex).unwrap().try_into().unwrap()
}

#[test]
fn multi_message_session_is_rejected() {
    // 2-of-3 group; sign with members {1,2}.
    let pkg =
        generate_dealer_package(2, 3, &[s32(&"11".repeat(32)), s32(&"22".repeat(32))]).unwrap();
    let signers = &pkg.shares[..2];

    let nonce_pairs: Vec<_> = signers
        .iter()
        .map(|s| generate_nonce_pair(&s.seckey))
        .collect();
    let member_nonces: Vec<MemberNonce> = signers
        .iter()
        .zip(&nonce_pairs)
        .map(|(s, n)| to_member_nonce(n.clone(), s.idx))
        .collect();

    // The attack needed THREE messages under one nonce. The session must refuse
    // to be built at all, so the partial sigs that leak the share never exist.
    let messages: Vec<(Vec<u8>, Vec<[u8; 32]>)> = vec![
        (b"transfer 1 BTC to alice".to_vec(), vec![]),
        (b"transfer 2 BTC to bob".to_vec(), vec![]),
        (b"transfer 3 BTC to carol".to_vec(), vec![]),
    ];
    let result = create_sign_session(&pkg.group, vec![1, 2], messages, member_nonces);

    assert!(
        result.is_err(),
        "multi-message session must be rejected — it is the precondition for \
         nonce-reuse share recovery"
    );
}

#[test]
fn single_message_session_still_signs() {
    // The fix must not break the legitimate one-message-per-nonce path.
    let pkg =
        generate_dealer_package(2, 3, &[s32(&"11".repeat(32)), s32(&"22".repeat(32))]).unwrap();
    let signers = &pkg.shares[..2];

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

    let messages = vec![(b"transfer 1 BTC to alice".to_vec(), vec![])];
    let session = create_sign_session(&pkg.group, vec![1, 2], messages, member_nonces).unwrap();

    let psigs: Vec<_> = signers
        .iter()
        .zip(&secret_nonces)
        .map(|(share, snonce)| {
            let pkg = create_partial_sig_package(&session, share, snonce).unwrap();
            assert_eq!(pkg.psigs.len(), 1, "one message ⇒ one partial sig");
            pkg
        })
        .collect();

    let sigs = combine_signatures(&session, &pkg.group, &psigs).unwrap();
    assert_eq!(sigs.len(), 1);
}
