/// Primitive-level tests for helpers, shares, verify_share, recover, and refresh.
///
/// These cover functionality not exercised by the higher-level flow tests:
/// TweakSeckey / TweakPubkey semantics, VerifyShare, GenRecoveryShares end-to-end,
/// and GenRefreshShares / RefreshShare correctness.
use frost_taproot::{
    group::create_dealer_set,
    helpers::{get_pubkey, tweak_pubkey, tweak_seckey},
    recover::{gen_recovery_shares, recover_share},
    refresh::{gen_refresh_shares, refresh_share},
    shares::{derive_shares_secret, verify_share},
    types::SecretShare,
};

fn s32(hex: &str) -> [u8; 32] {
    hex::decode(hex).unwrap().try_into().unwrap()
}

fn p33(hex: &str) -> [u8; 33] {
    hex::decode(hex).unwrap().try_into().unwrap()
}

const S0: &str = "0070ca75929ca1ec4cd70ac34f46079bdfdd87f9d0c0bf4275f3882f7b462d0f";
const S1: &str = "0e0376a7180253cdb8b6020bff0eda529760da65e715663e2152e4be2fc7b443";
const SECKEY: &str = "0e74411caa9ef5ba058d0ccf4e54e1ee773e625fb7d6258097466cedab0de152";
const PUBKEY: &str = "0278f55809a11a1016d13ec4f54674810abe4a6fec8b586e14f90d0c1f80de33eb";

// ── TweakSeckey ───────────────────────────────────────────────────────────────

#[test]
fn tweak_seckey_by_zero_is_identity() {
    let seckey = s32(SECKEY);
    let zero = s32("0000000000000000000000000000000000000000000000000000000000000000");
    assert_eq!(tweak_seckey(&seckey, &zero), seckey);
}

#[test]
fn tweak_seckey_by_one_increments_scalar() {
    use frost_taproot::ecc::util::{scalar_from_bytes, scalar_to_bytes};
    use k256::Scalar;
    let seckey = s32(SECKEY);
    let one = s32("0000000000000000000000000000000000000000000000000000000000000001");
    let tweaked = tweak_seckey(&seckey, &one);
    let expected = scalar_to_bytes(&(scalar_from_bytes(&seckey) + Scalar::ONE));
    assert_eq!(tweaked, expected);
}

// TweakSeckey(sk, t) must produce the same pubkey as TweakPubkey(pk, t).
#[test]
fn tweak_seckey_consistent_with_tweak_pubkey() {
    let seckey = s32(SECKEY);
    let pubkey = p33(PUBKEY);
    let tweak = s32("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

    let tweaked_sk = tweak_seckey(&seckey, &tweak);
    let pk_from_tweaked_sk = get_pubkey(&tweaked_sk);
    let tweaked_pk_direct = tweak_pubkey(&pubkey, &tweak).unwrap();

    assert_eq!(
        pk_from_tweaked_sk, tweaked_pk_direct,
        "tweaked sk pubkey must equal directly tweaked pk"
    );
}

// ── TweakPubkey ───────────────────────────────────────────────────────────────

#[test]
fn tweak_pubkey_by_zero_is_identity() {
    let pubkey = p33(PUBKEY);
    let zero = s32("0000000000000000000000000000000000000000000000000000000000000000");
    let tweaked = tweak_pubkey(&pubkey, &zero).unwrap();
    assert_eq!(tweaked, pubkey, "tweak by zero must be identity");
}

#[test]
fn tweak_pubkey_by_one_adds_generator() {
    use frost_taproot::ecc::group::{element_add, scalar_base_multi};
    use frost_taproot::ecc::util::{lift_x, serialize_point};
    use k256::Scalar;
    let pubkey = p33(PUBKEY);
    let one = s32("0000000000000000000000000000000000000000000000000000000000000001");
    let tweaked = tweak_pubkey(&pubkey, &one).unwrap();
    let pt = lift_x(&pubkey).unwrap();
    let g = scalar_base_multi(&Scalar::ONE);
    let expected = serialize_point(&element_add(Some(pt), Some(g)).unwrap());
    assert_eq!(tweaked, expected);
}

#[test]
fn tweak_pubkey_invalid_length_errors() {
    let one = s32("0000000000000000000000000000000000000000000000000000000000000001");
    assert!(tweak_pubkey(&[0u8; 31], &one).is_err());
    assert!(tweak_pubkey(&[0u8; 34], &one).is_err());
}

// ── VerifyShare ───────────────────────────────────────────────────────────────

#[test]
fn verify_share_valid_shares() {
    let secrets = [s32(S0), s32(S1)];
    let group = create_dealer_set(2, 3, &secrets).unwrap();
    for share in &group.shares {
        assert!(
            verify_share(&group.vss_commits, share, 2).unwrap(),
            "share {} should be valid",
            share.idx
        );
    }
}

#[test]
fn verify_share_tampered_share_fails() {
    let secrets = [s32(S0), s32(S1)];
    let group = create_dealer_set(2, 3, &secrets).unwrap();
    let mut tampered = group.shares[0].clone();
    tampered.seckey[0] ^= 0xff;
    assert!(
        !verify_share(&group.vss_commits, &tampered, 2).unwrap(),
        "tampered share should fail verification"
    );
}

// ── GenRecoveryShares / RecoverShare ─────────────────────────────────────────

#[test]
fn gen_recovery_shares_reconstructs_lost_share() {
    let secrets = [s32(S0), s32(S1)];
    let group = create_dealer_set(2, 3, &secrets).unwrap();
    let members = [2u32, 3u32];

    let pkg2 = gen_recovery_shares(&members, &group.shares[1], 1, 2, &[s32(S0)]).unwrap();
    let pkg3 = gen_recovery_shares(&members, &group.shares[2], 1, 2, &[s32(S1)]).unwrap();

    // Each member aggregates the repair shares they received from all helpers.
    use frost_taproot::ecc::util::{scalar_from_bytes, scalar_to_bytes};
    let agg = |idx: u32| -> SecretShare {
        let a = scalar_from_bytes(&pkg2.shares.iter().find(|s| s.idx == idx).unwrap().seckey);
        let b = scalar_from_bytes(&pkg3.shares.iter().find(|s| s.idx == idx).unwrap().seckey);
        SecretShare {
            idx,
            seckey: scalar_to_bytes(&(a + b)),
        }
    };

    let repaired = recover_share(&[agg(2), agg(3)], 1);
    assert_eq!(repaired.idx, 1);
    assert_eq!(
        repaired.seckey, group.shares[0].seckey,
        "recovered share must match original"
    );
}

#[test]
fn gen_recovery_shares_members_exceed_threshold_errors() {
    let secrets = [s32(S0), s32(S1)];
    let group = create_dealer_set(2, 3, &secrets).unwrap();
    // 3 members but threshold=2 → repair_shares has 2 entries, members has 3
    assert!(gen_recovery_shares(&[2u32, 3u32, 4u32], &group.shares[1], 1, 2, &[]).is_err());
}

#[test]
fn gen_recovery_shares_not_enough_members_errors() {
    let secrets = [s32(S0), s32(S1)];
    let group = create_dealer_set(2, 3, &secrets).unwrap();
    assert!(gen_recovery_shares(&[2u32], &group.shares[1], 1, 2, &[]).is_err());
}

// ── GenRefreshShares / RefreshShare ──────────────────────────────────────────

#[test]
fn refresh_share_preserves_secret() {
    let secrets = [s32(S0), s32(S1)];
    let group = create_dealer_set(2, 3, &secrets).unwrap();

    let rp1 = gen_refresh_shares(
        1,
        2,
        3,
        &[s32(
            "1111111111111111111111111111111111111111111111111111111111111111",
        )],
    )
    .unwrap();
    let rp2 = gen_refresh_shares(
        2,
        2,
        3,
        &[s32(
            "2222222222222222222222222222222222222222222222222222222222222222",
        )],
    )
    .unwrap();
    let rp3 = gen_refresh_shares(
        3,
        2,
        3,
        &[s32(
            "3333333333333333333333333333333333333333333333333333333333333333",
        )],
    )
    .unwrap();

    let collect = |idx: u32| -> Vec<SecretShare> {
        [&rp1, &rp2, &rp3]
            .iter()
            .map(|pkg| pkg.shares.iter().find(|s| s.idx == idx).unwrap().clone())
            .collect()
    };

    let new1 = refresh_share(&collect(1), &group.shares[0]).unwrap();
    let new2 = refresh_share(&collect(2), &group.shares[1]).unwrap();

    let recovered = derive_shares_secret(&[new1, new2]).unwrap();
    assert_eq!(recovered, s32(S0), "secret must be unchanged after refresh");
}

#[test]
fn refresh_share_changes_share_values() {
    let secrets = [s32(S0), s32(S1)];
    let group = create_dealer_set(2, 3, &secrets).unwrap();
    let rp1 = gen_refresh_shares(
        1,
        2,
        3,
        &[s32(
            "1111111111111111111111111111111111111111111111111111111111111111",
        )],
    )
    .unwrap();

    let agg1: Vec<SecretShare> = rp1.shares.iter().filter(|s| s.idx == 1).cloned().collect();
    let new1 = refresh_share(&agg1, &group.shares[0]).unwrap();

    assert_ne!(
        new1.seckey, group.shares[0].seckey,
        "refreshed share should differ"
    );
    assert_eq!(new1.idx, group.shares[0].idx);
}

#[test]
fn refresh_share_polynomial_has_zero_constant_term() {
    use frost_taproot::ecc::util::scalar_from_bytes;
    use frost_taproot::poly::index_to_scalar;
    use frost_taproot::poly::interpolate_root;

    let pkg = gen_refresh_shares(
        1,
        2,
        3,
        &[s32(
            "1111111111111111111111111111111111111111111111111111111111111111",
        )],
    )
    .unwrap();
    let points: Vec<_> = pkg
        .shares
        .iter()
        .map(|s| (index_to_scalar(s.idx), scalar_from_bytes(&s.seckey)))
        .collect();
    let root = interpolate_root(&points).unwrap();
    assert_eq!(
        root,
        k256::Scalar::ZERO,
        "refresh polynomial must have f(0) = 0"
    );
}
