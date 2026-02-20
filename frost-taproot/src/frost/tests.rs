#[cfg(test)]
mod dealer_tests {
    use crate::frost::dealer::*;
    use crate::frost::types::*;

    fn s32(hex: &str) -> [u8; 32] {
        hex::decode(hex).unwrap().try_into().unwrap()
    }

    const S0: &str = "0070ca75929ca1ec4cd70ac34f46079bdfdd87f9d0c0bf4275f3882f7b462d0f";
    const S1: &str = "0e0376a7180253cdb8b6020bff0eda529760da65e715663e2152e4be2fc7b443";

    #[test]
    fn generate_dealer_package_structure() {
        let pkg = generate_dealer_package(2, 3, &[]).unwrap();
        assert_eq!(pkg.group.threshold, 2);
        assert_eq!(pkg.group.members.len(), 3);
        assert_eq!(pkg.shares.len(), 3);
        for (i, share) in pkg.shares.iter().enumerate() {
            assert_eq!(share.idx as usize, i + 1);
            assert_eq!(pkg.group.members[i].idx, share.idx);
        }
    }

    #[test]
    fn generate_dealer_package_deterministic_with_secrets() {
        let secrets = [s32(S0), s32(S1)];
        let a = generate_dealer_package(2, 3, &secrets).unwrap();
        let b = generate_dealer_package(2, 3, &secrets).unwrap();
        assert_eq!(a.group.group_pk, b.group.group_pk);
        for (sa, sb) in a.shares.iter().zip(b.shares.iter()) {
            assert_eq!(sa.seckey, sb.seckey);
        }
    }

    #[test]
    fn generate_dealer_package_random_without_secrets() {
        let a = generate_dealer_package(2, 3, &[]).unwrap();
        let b = generate_dealer_package(2, 3, &[]).unwrap();
        assert_ne!(a.group.group_pk, b.group.group_pk);
    }

    #[test]
    fn generate_dealer_package_member_pubkeys_match_shares() {
        let secrets = [s32(S0), s32(S1)];
        let pkg = generate_dealer_package(2, 3, &secrets).unwrap();
        for share in &pkg.shares {
            let expected_pk = crate::helpers::get_pubkey(&share.seckey);
            let member = pkg
                .group
                .members
                .iter()
                .find(|m| m.idx == share.idx)
                .unwrap();
            assert_eq!(member.pubkey, expected_pk);
        }
    }

    #[test]
    fn generate_dealer_package_matches_fixture() {
        let secrets = [s32(S0), s32(S1)];
        let pkg = generate_dealer_package(2, 3, &secrets).unwrap();
        assert_eq!(
            hex::encode(pkg.group.group_pk),
            "021ae63bc9ddaffe52d44c3018e83115bfb22195bd8112fcad112310714e6fd5ec"
        );
        assert_eq!(
            hex::encode(pkg.shares[0].seckey),
            "0e74411caa9ef5ba058d0ccf4e54e1ee773e625fb7d6258097466cedab0de152"
        );
    }

    #[test]
    fn get_group_id_is_deterministic() {
        let secrets = [s32(S0), s32(S1)];
        let pkg = generate_dealer_package(2, 3, &secrets).unwrap();
        let id1 = get_group_id(&pkg.group);
        let id2 = get_group_id(&pkg.group);
        assert_eq!(id1, id2);
    }

    #[test]
    fn get_group_id_differs_for_different_groups() {
        let a = generate_dealer_package(2, 3, &[]).unwrap();
        let b = generate_dealer_package(2, 3, &[]).unwrap();
        assert_ne!(get_group_id(&a.group), get_group_id(&b.group));
    }

    #[test]
    fn get_group_id_differs_for_different_thresholds() {
        let secrets = [s32(S0), s32(S1)];
        let a = generate_dealer_package(2, 3, &secrets).unwrap();
        // Same secrets but different threshold → different group
        let b = generate_dealer_package(3, 3, &secrets).unwrap();
        assert_ne!(get_group_id(&a.group), get_group_id(&b.group));
    }

    #[test]
    fn is_group_member_valid_shares() {
        let secrets = [s32(S0), s32(S1)];
        let pkg = generate_dealer_package(2, 3, &secrets).unwrap();
        for share in &pkg.shares {
            assert!(is_group_member(&pkg.group, share));
        }
    }

    #[test]
    fn is_group_member_wrong_seckey_fails() {
        let secrets = [s32(S0), s32(S1)];
        let pkg = generate_dealer_package(2, 3, &secrets).unwrap();
        let tampered = SharePackage {
            idx: pkg.shares[0].idx,
            seckey: s32("1111111111111111111111111111111111111111111111111111111111111111"),
        };
        assert!(!is_group_member(&pkg.group, &tampered));
    }

    #[test]
    fn is_group_member_wrong_idx_fails() {
        let secrets = [s32(S0), s32(S1)];
        let pkg = generate_dealer_package(2, 3, &secrets).unwrap();
        let tampered = SharePackage {
            idx: 99,
            seckey: pkg.shares[0].seckey,
        };
        assert!(!is_group_member(&pkg.group, &tampered));
    }

    #[test]
    fn verify_dealer_package_valid() {
        let secrets = [s32(S0), s32(S1)];
        let pkg = generate_dealer_package(2, 3, &secrets).unwrap();
        assert!(verify_dealer_package(&pkg).unwrap());
    }

    #[test]
    fn verify_dealer_package_tampered_share_fails() {
        let secrets = [s32(S0), s32(S1)];
        let mut pkg = generate_dealer_package(2, 3, &secrets).unwrap();
        pkg.shares[0].seckey[0] ^= 0xff;
        assert!(!verify_dealer_package(&pkg).unwrap());
    }

    #[test]
    fn get_member_by_idx_found() {
        let secrets = [s32(S0), s32(S1)];
        let pkg = generate_dealer_package(2, 3, &secrets).unwrap();
        let m = get_member_by_idx(&pkg.group, 2).unwrap();
        assert_eq!(m.idx, 2);
    }

    #[test]
    fn get_member_by_idx_not_found() {
        let secrets = [s32(S0), s32(S1)];
        let pkg = generate_dealer_package(2, 3, &secrets).unwrap();
        assert!(get_member_by_idx(&pkg.group, 99).is_none());
    }

    #[test]
    fn get_member_by_pubkey_found() {
        let secrets = [s32(S0), s32(S1)];
        let pkg = generate_dealer_package(2, 3, &secrets).unwrap();
        let pk = pkg.group.members[1].pubkey;
        let m = get_member_by_pubkey(&pkg.group, &pk).unwrap();
        assert_eq!(m.idx, 2);
    }
}

#[cfg(test)]
mod nonce_tests {
    use crate::frost::nonce::*;
    use crate::frost::types::*;

    fn s32(hex: &str) -> [u8; 32] {
        hex::decode(hex).unwrap().try_into().unwrap()
    }

    const SECRET: &str = "0e74411caa9ef5ba058d0ccf4e54e1ee773e625fb7d6258097466cedab0de152";

    #[test]
    fn generate_nonce_pair_produces_valid_points() {
        let secret = s32(SECRET);
        let nonce = generate_nonce_pair(&secret);
        assert!(validate_nonce(&nonce));
    }

    #[test]
    fn generate_nonce_pair_is_random() {
        let secret = s32(SECRET);
        let a = generate_nonce_pair(&secret);
        let b = generate_nonce_pair(&secret);
        // Different codes → different nonces
        assert_ne!(a.code, b.code);
        assert_ne!(a.binder_pn, b.binder_pn);
        assert_ne!(a.hidden_pn, b.hidden_pn);
    }

    #[test]
    fn generate_nonce_pairs_count() {
        let secret = s32(SECRET);
        let pairs = generate_nonce_pairs(&secret, 5);
        assert_eq!(pairs.len(), 5);
        // All codes should be unique
        let codes: std::collections::HashSet<_> = pairs.iter().map(|p| p.code).collect();
        assert_eq!(codes.len(), 5);
    }

    #[test]
    fn derive_secret_nonce_roundtrip() {
        let secret = s32(SECRET);
        let nonce = generate_nonce_pair(&secret);
        let derived = derive_secret_nonce(&secret, &nonce.code);
        // Re-derived public nonces must match the originals
        let binder_pn = crate::helpers::get_pubkey(&derived.binder_sn);
        let hidden_pn = crate::helpers::get_pubkey(&derived.hidden_sn);
        assert_eq!(binder_pn, nonce.binder_pn);
        assert_eq!(hidden_pn, nonce.hidden_pn);
    }

    #[test]
    fn derive_secret_nonce_deterministic() {
        let secret = s32(SECRET);
        let code = [0x42u8; 32];
        let a = derive_secret_nonce(&secret, &code);
        let b = derive_secret_nonce(&secret, &code);
        assert_eq!(a.binder_sn, b.binder_sn);
        assert_eq!(a.hidden_sn, b.hidden_sn);
    }

    #[test]
    fn derive_secret_nonce_different_codes_differ() {
        let secret = s32(SECRET);
        let code_a = [0x01u8; 32];
        let code_b = [0x02u8; 32];
        let a = derive_secret_nonce(&secret, &code_a);
        let b = derive_secret_nonce(&secret, &code_b);
        assert_ne!(a.binder_sn, b.binder_sn);
        assert_ne!(a.hidden_sn, b.hidden_sn);
    }

    #[test]
    fn derive_secret_nonce_different_secrets_differ() {
        let secret_a = s32(SECRET);
        let secret_b = s32("1c77b7c3c2a14987be430edb4d63bc410e9f3cc59eeb8bbeb89951abdad59595");
        let code = [0x42u8; 32];
        let a = derive_secret_nonce(&secret_a, &code);
        let b = derive_secret_nonce(&secret_b, &code);
        assert_ne!(a.binder_sn, b.binder_sn);
    }

    #[test]
    fn verify_nonce_code_valid() {
        let secret = s32(SECRET);
        let derived = generate_nonce_pair(&secret);
        let member_nonce = to_member_nonce(derived, 1);
        assert!(verify_nonce_code(&secret, &member_nonce));
    }

    #[test]
    fn verify_nonce_code_wrong_secret_fails() {
        let secret = s32(SECRET);
        let wrong_secret = s32("1c77b7c3c2a14987be430edb4d63bc410e9f3cc59eeb8bbeb89951abdad59595");
        let derived = generate_nonce_pair(&secret);
        let member_nonce = to_member_nonce(derived, 1);
        assert!(!verify_nonce_code(&wrong_secret, &member_nonce));
    }

    #[test]
    fn verify_nonce_code_tampered_code_fails() {
        let secret = s32(SECRET);
        let derived = generate_nonce_pair(&secret);
        let mut member_nonce = to_member_nonce(derived, 1);
        member_nonce.code[0] ^= 0xff;
        assert!(!verify_nonce_code(&secret, &member_nonce));
    }

    #[test]
    fn to_member_nonce_attaches_idx() {
        let secret = s32(SECRET);
        let derived = generate_nonce_pair(&secret);
        let binder_pn = derived.binder_pn;
        let hidden_pn = derived.hidden_pn;
        let code = derived.code;
        let member = to_member_nonce(derived, 42);
        assert_eq!(member.idx, 42);
        assert_eq!(member.binder_pn, binder_pn);
        assert_eq!(member.hidden_pn, hidden_pn);
        assert_eq!(member.code, code);
    }

    #[test]
    fn validate_nonce_valid() {
        let secret = s32(SECRET);
        let nonce = generate_nonce_pair(&secret);
        assert!(validate_nonce(&nonce));
    }

    #[test]
    fn validate_nonce_invalid_point_fails() {
        let bad = DerivedNonce {
            binder_pn: [0u8; 33],
            hidden_pn: [0u8; 33],
            code: [0u8; 32],
        };
        assert!(!validate_nonce(&bad));
    }
}

#[cfg(test)]
mod signing_tests {
    use crate::frost::dealer::generate_dealer_package;
    use crate::frost::nonce::{derive_secret_nonce, generate_nonce_pair, to_member_nonce};
    use crate::frost::signing::*;
    use crate::frost::types::*;

    fn s32(hex: &str) -> [u8; 32] {
        hex::decode(hex).unwrap().try_into().unwrap()
    }

    const S0: &str = "0070ca75929ca1ec4cd70ac34f46079bdfdd87f9d0c0bf4275f3882f7b462d0f";
    const S1: &str = "0e0376a7180253cdb8b6020bff0eda529760da65e715663e2152e4be2fc7b443";

    /// Build a complete 2-of-3 signing setup with deterministic inputs.
    fn setup_session(
        message: &[u8],
        tweaks: Vec<[u8; 32]>,
    ) -> (
        crate::frost::types::DealerPackage,
        SignSession,
        Vec<SecretNoncePair>,
    ) {
        let secrets = [s32(S0), s32(S1)];
        let pkg = generate_dealer_package(2, 3, &secrets).unwrap();

        // Participants 1 and 2 sign
        let signing_shares = &pkg.shares[..2];

        // Each generates a nonce pair
        let nonce_pairs: Vec<_> = signing_shares
            .iter()
            .map(|s| generate_nonce_pair(&s.seckey))
            .collect();

        let member_nonces: Vec<MemberNonce> = signing_shares
            .iter()
            .zip(nonce_pairs.iter())
            .map(|(s, n)| to_member_nonce(n.clone(), s.idx))
            .collect();

        let secret_nonces: Vec<SecretNoncePair> = signing_shares
            .iter()
            .zip(nonce_pairs.iter())
            .map(|(s, n)| derive_secret_nonce(&s.seckey, &n.code))
            .collect();

        let members: Vec<u32> = signing_shares.iter().map(|s| s.idx).collect();
        let session = create_sign_session(
            &pkg.group,
            members,
            vec![(message.to_vec(), tweaks)],
            member_nonces,
        )
        .unwrap();

        (pkg, session, secret_nonces)
    }

    // ── create_sign_session ───────────────────────────────────────────────────

    #[test]
    fn create_sign_session_sorts_members() {
        let secrets = [s32(S0), s32(S1)];
        let pkg = generate_dealer_package(2, 3, &secrets).unwrap();
        let nonces: Vec<MemberNonce> = pkg.shares[..2]
            .iter()
            .map(|s| to_member_nonce(generate_nonce_pair(&s.seckey), s.idx))
            .collect();
        // Pass members in reverse order
        let session = create_sign_session(
            &pkg.group,
            vec![2, 1],
            vec![(b"hello".to_vec(), vec![])],
            nonces,
        )
        .unwrap();
        assert_eq!(session.members, vec![1, 2]);
    }

    #[test]
    fn create_sign_session_nonce_count_mismatch_errors() {
        let secrets = [s32(S0), s32(S1)];
        let pkg = generate_dealer_package(2, 3, &secrets).unwrap();
        let nonces: Vec<MemberNonce> = pkg.shares[..1]
            .iter()
            .map(|s| to_member_nonce(generate_nonce_pair(&s.seckey), s.idx))
            .collect();
        let result = create_sign_session(
            &pkg.group,
            vec![1, 2], // 2 members but only 1 nonce
            vec![(b"hello".to_vec(), vec![])],
            nonces,
        );
        assert!(result.is_err());
    }

    #[test]
    fn create_sign_session_id_is_deterministic() {
        let secrets = [s32(S0), s32(S1)];
        let pkg = generate_dealer_package(2, 3, &secrets).unwrap();
        let msg = b"test message";

        // Build two sessions with the same nonces
        let nonce_pairs: Vec<_> = pkg.shares[..2]
            .iter()
            .map(|s| generate_nonce_pair(&s.seckey))
            .collect();
        let member_nonces: Vec<MemberNonce> = pkg.shares[..2]
            .iter()
            .zip(nonce_pairs.iter())
            .map(|(s, n)| to_member_nonce(n.clone(), s.idx))
            .collect();

        let s1 = create_sign_session(
            &pkg.group,
            vec![1, 2],
            vec![(msg.to_vec(), vec![])],
            member_nonces.clone(),
        )
        .unwrap();
        let s2 = create_sign_session(
            &pkg.group,
            vec![1, 2],
            vec![(msg.to_vec(), vec![])],
            member_nonces,
        )
        .unwrap();
        assert_eq!(s1.sid, s2.sid);
    }

    #[test]
    fn create_sign_session_id_differs_for_different_messages() {
        let secrets = [s32(S0), s32(S1)];
        let pkg = generate_dealer_package(2, 3, &secrets).unwrap();
        let nonce_pairs: Vec<_> = pkg.shares[..2]
            .iter()
            .map(|s| generate_nonce_pair(&s.seckey))
            .collect();
        let make_nonces = || {
            pkg.shares[..2]
                .iter()
                .zip(nonce_pairs.iter())
                .map(|(s, n)| to_member_nonce(n.clone(), s.idx))
                .collect::<Vec<_>>()
        };
        let s1 = create_sign_session(
            &pkg.group,
            vec![1, 2],
            vec![(b"msg1".to_vec(), vec![])],
            make_nonces(),
        )
        .unwrap();
        let s2 = create_sign_session(
            &pkg.group,
            vec![1, 2],
            vec![(b"msg2".to_vec(), vec![])],
            make_nonces(),
        )
        .unwrap();
        assert_ne!(s1.sid, s2.sid);
    }

    // ── create_partial_sig_package ────────────────────────────────────────────

    #[test]
    fn create_partial_sig_package_produces_correct_count() {
        let msg = b"hello world";
        let (pkg, session, secret_nonces) = setup_session(msg, vec![]);
        let psig = create_partial_sig_package(&session, &pkg.shares[0], &secret_nonces[0]).unwrap();
        assert_eq!(psig.psigs.len(), 1);
        assert_eq!(psig.idx, 1);
        assert_eq!(psig.sid, session.sid);
    }

    #[test]
    fn create_partial_sig_package_multi_message() {
        let secrets = [s32(S0), s32(S1)];
        let pkg = generate_dealer_package(2, 3, &secrets).unwrap();
        let nonce_pairs: Vec<_> = pkg.shares[..2]
            .iter()
            .map(|s| generate_nonce_pair(&s.seckey))
            .collect();
        let member_nonces: Vec<MemberNonce> = pkg.shares[..2]
            .iter()
            .zip(nonce_pairs.iter())
            .map(|(s, n)| to_member_nonce(n.clone(), s.idx))
            .collect();
        let secret_nonces: Vec<SecretNoncePair> = pkg.shares[..2]
            .iter()
            .zip(nonce_pairs.iter())
            .map(|(s, n)| derive_secret_nonce(&s.seckey, &n.code))
            .collect();

        let messages = vec![
            (b"message one".to_vec(), vec![]),
            (b"message two".to_vec(), vec![]),
        ];
        let session = create_sign_session(&pkg.group, vec![1, 2], messages, member_nonces).unwrap();

        let psig = create_partial_sig_package(&session, &pkg.shares[0], &secret_nonces[0]).unwrap();
        assert_eq!(psig.psigs.len(), 2);
    }

    // ── verify_partial_sig_package ────────────────────────────────────────────

    #[test]
    fn verify_partial_sig_package_valid() {
        let msg = b"hello world";
        let (pkg, session, secret_nonces) = setup_session(msg, vec![]);
        let psig = create_partial_sig_package(&session, &pkg.shares[0], &secret_nonces[0]).unwrap();
        let result = verify_partial_sig_package(&session, &pkg.group, &psig).unwrap();
        assert!(result.is_none(), "expected valid, got: {:?}", result);
    }

    #[test]
    fn verify_partial_sig_package_wrong_sid_fails() {
        let msg = b"hello world";
        let (pkg, session, secret_nonces) = setup_session(msg, vec![]);
        let mut psig =
            create_partial_sig_package(&session, &pkg.shares[0], &secret_nonces[0]).unwrap();
        psig.sid = [0xff; 32];
        let result = verify_partial_sig_package(&session, &pkg.group, &psig).unwrap();
        assert!(result.is_some());
    }

    #[test]
    fn verify_partial_sig_package_wrong_pubkey_fails() {
        let msg = b"hello world";
        let (pkg, session, secret_nonces) = setup_session(msg, vec![]);
        let mut psig =
            create_partial_sig_package(&session, &pkg.shares[0], &secret_nonces[0]).unwrap();
        psig.pubkey = [0x02; 33]; // not in group
        let result = verify_partial_sig_package(&session, &pkg.group, &psig).unwrap();
        assert!(result.is_some());
    }

    #[test]
    fn verify_partial_sig_package_tampered_psig_fails() {
        let msg = b"hello world";
        let (pkg, session, secret_nonces) = setup_session(msg, vec![]);
        let mut psig =
            create_partial_sig_package(&session, &pkg.shares[0], &secret_nonces[0]).unwrap();
        psig.psigs[0].psig[0] ^= 0xff;
        let result = verify_partial_sig_package(&session, &pkg.group, &psig).unwrap();
        assert!(result.is_some());
    }

    // ── combine_signatures ────────────────────────────────────────────────────

    #[test]
    fn combine_signatures_produces_valid_bip340() {
        let msg = b"hello world";
        let (pkg, session, secret_nonces) = setup_session(msg, vec![]);

        let psig1 =
            create_partial_sig_package(&session, &pkg.shares[0], &secret_nonces[0]).unwrap();
        let psig2 =
            create_partial_sig_package(&session, &pkg.shares[1], &secret_nonces[1]).unwrap();

        let sigs = combine_signatures(&session, &pkg.group, &[psig1, psig2]).unwrap();
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].message, msg);
        assert_eq!(sigs[0].sig.len(), 64);
    }

    #[test]
    fn combine_signatures_with_tweaks() {
        let msg = b"tweaked message";
        let tweak = s32("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let (pkg, session, secret_nonces) = setup_session(msg, vec![tweak]);

        let psig1 =
            create_partial_sig_package(&session, &pkg.shares[0], &secret_nonces[0]).unwrap();
        let psig2 =
            create_partial_sig_package(&session, &pkg.shares[1], &secret_nonces[1]).unwrap();

        let sigs = combine_signatures(&session, &pkg.group, &[psig1, psig2]).unwrap();
        assert_eq!(sigs.len(), 1);
        // The pubkey in the signature should be the tweaked group key
        assert_ne!(sigs[0].pubkey, pkg.group.group_pk);
    }

    #[test]
    fn combine_signatures_multi_message() {
        let secrets = [s32(S0), s32(S1)];
        let pkg = generate_dealer_package(2, 3, &secrets).unwrap();
        let nonce_pairs: Vec<_> = pkg.shares[..2]
            .iter()
            .map(|s| generate_nonce_pair(&s.seckey))
            .collect();
        let member_nonces: Vec<MemberNonce> = pkg.shares[..2]
            .iter()
            .zip(nonce_pairs.iter())
            .map(|(s, n)| to_member_nonce(n.clone(), s.idx))
            .collect();
        let secret_nonces: Vec<SecretNoncePair> = pkg.shares[..2]
            .iter()
            .zip(nonce_pairs.iter())
            .map(|(s, n)| derive_secret_nonce(&s.seckey, &n.code))
            .collect();

        let messages = vec![
            (b"first message".to_vec(), vec![]),
            (b"second message".to_vec(), vec![]),
        ];
        let session =
            create_sign_session(&pkg.group, vec![1, 2], messages.clone(), member_nonces).unwrap();

        let psig1 =
            create_partial_sig_package(&session, &pkg.shares[0], &secret_nonces[0]).unwrap();
        let psig2 =
            create_partial_sig_package(&session, &pkg.shares[1], &secret_nonces[1]).unwrap();

        let sigs = combine_signatures(&session, &pkg.group, &[psig1, psig2]).unwrap();
        assert_eq!(sigs.len(), 2);
        assert_eq!(sigs[0].message, messages[0].0);
        assert_eq!(sigs[1].message, messages[1].0);
    }

    #[test]
    fn combine_signatures_below_threshold_errors() {
        let msg = b"hello world";
        let (pkg, session, secret_nonces) = setup_session(msg, vec![]);
        let psig1 =
            create_partial_sig_package(&session, &pkg.shares[0], &secret_nonces[0]).unwrap();
        // Only 1 partial sig for a 2-of-3 group
        let result = combine_signatures(&session, &pkg.group, &[psig1]);
        assert!(result.is_err());
    }

    #[test]
    fn full_signing_flow_matches_fixture() {
        // Use the same deterministic inputs as the integration test fixture
        let secrets = [s32(S0), s32(S1)];
        let pkg = generate_dealer_package(2, 3, &secrets).unwrap();

        let hidden_seed = s32("0070ca75929ca1ec4cd70ac34f46079bdfdd87f9d0c0bf4275f3882f7b462d0f");
        let binder_seed = s32("0e0376a7180253cdb8b6020bff0eda529760da65e715663e2152e4be2fc7b443");

        // Build nonces using the low-level generate_nonce to match fixture
        let hidden_sn1 = crate::helpers::generate_nonce(&pkg.shares[0].seckey, Some(&hidden_seed));
        let binder_sn1 = crate::helpers::generate_nonce(&pkg.shares[0].seckey, Some(&binder_seed));
        let hidden_sn2 = crate::helpers::generate_nonce(&pkg.shares[1].seckey, Some(&hidden_seed));
        let binder_sn2 = crate::helpers::generate_nonce(&pkg.shares[1].seckey, Some(&binder_seed));

        let member_nonces = vec![
            MemberNonce {
                idx: 1,
                hidden_pn: crate::helpers::get_pubkey(&hidden_sn1),
                binder_pn: crate::helpers::get_pubkey(&binder_sn1),
                code: [0u8; 32], // code unused in this path
            },
            MemberNonce {
                idx: 2,
                hidden_pn: crate::helpers::get_pubkey(&hidden_sn2),
                binder_pn: crate::helpers::get_pubkey(&binder_sn2),
                code: [0u8; 32],
            },
        ];

        let tweaks = vec![
            s32("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            s32("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
        ];
        let message = hex::decode("68656c6c6f20776f726c6421").unwrap();

        let session = create_sign_session(
            &pkg.group,
            vec![1, 2],
            vec![(message.clone(), tweaks)],
            member_nonces,
        )
        .unwrap();

        let secret_nonce1 = SecretNoncePair {
            code: [0u8; 32],
            hidden_sn: hidden_sn1,
            binder_sn: binder_sn1,
        };
        let secret_nonce2 = SecretNoncePair {
            code: [0u8; 32],
            hidden_sn: hidden_sn2,
            binder_sn: binder_sn2,
        };

        let psig1 = create_partial_sig_package(&session, &pkg.shares[0], &secret_nonce1).unwrap();
        let psig2 = create_partial_sig_package(&session, &pkg.shares[1], &secret_nonce2).unwrap();

        // Verify each partial sig
        assert!(verify_partial_sig_package(&session, &pkg.group, &psig1)
            .unwrap()
            .is_none());
        assert!(verify_partial_sig_package(&session, &pkg.group, &psig2)
            .unwrap()
            .is_none());

        // Combine and verify final signature
        let sigs = combine_signatures(&session, &pkg.group, &[psig1, psig2]).unwrap();
        assert_eq!(sigs.len(), 1);
        assert_eq!(
            hex::encode(sigs[0].sig),
            "e76328e49c27c12392a117d39ef9f5def368590d5e72438907fb63c1006fd5891d715fa750b5840610aaf531949f633c4555ac20caf290c3f22cc0771f074447"
        );
    }
}

#[cfg(test)]
mod ecdh_tests {
    use crate::frost::dealer::generate_dealer_package;
    use crate::frost::ecdh::*;
    use crate::frost::types::*;

    fn s32(hex: &str) -> [u8; 32] {
        hex::decode(hex).unwrap().try_into().unwrap()
    }

    fn p33(hex: &str) -> [u8; 33] {
        hex::decode(hex).unwrap().try_into().unwrap()
    }

    const S0: &str = "0070ca75929ca1ec4cd70ac34f46079bdfdd87f9d0c0bf4275f3882f7b462d0f";
    const S1: &str = "0e0376a7180253cdb8b6020bff0eda529760da65e715663e2152e4be2fc7b443";

    fn demo_keypair() -> ([u8; 32], [u8; 33]) {
        let aux = s32("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let sk = crate::helpers::generate_seckey(Some(&aux));
        let pk = crate::helpers::get_pubkey(&sk);
        (sk, pk)
    }

    // ── create_ecdh_pkg ───────────────────────────────────────────────────────

    #[test]
    fn create_ecdh_pkg_structure() {
        let secrets = [s32(S0), s32(S1)];
        let pkg = generate_dealer_package(2, 3, &secrets).unwrap();
        let (_, demo_pk) = demo_keypair();
        let members = [1u32, 3u32];

        let ecdh = create_ecdh_pkg(&members, &demo_pk, &pkg.shares[0]).unwrap();
        assert_eq!(ecdh.idx, 1);
        assert_eq!(ecdh.members, members);
        assert_eq!(ecdh.entries.len(), 1);
        assert_eq!(ecdh.entries[0].ecdh_pk, demo_pk);
    }

    #[test]
    fn create_ecdh_pkg_matches_fixture() {
        let secrets = [s32(S0), s32(S1)];
        let pkg = generate_dealer_package(2, 3, &secrets).unwrap();
        let (_, demo_pk) = demo_keypair();
        let members = [1u32, 3u32];

        let ecdh1 = create_ecdh_pkg(&members, &demo_pk, &pkg.shares[0]).unwrap();
        let ecdh3 = create_ecdh_pkg(&members, &demo_pk, &pkg.shares[2]).unwrap();

        assert_eq!(
            hex::encode(ecdh1.entries[0].keyshare),
            "0386c5b0f4bace78ef17d02b09e339b5a39f659dbbf1f3f531b9825df6836cfea9"
        );
        assert_eq!(
            hex::encode(ecdh3.entries[0].keyshare),
            "023edaf055945d35006e1c52dd7a388e0c10b36eb55aa9d117853af87903cb54c0"
        );
    }

    // ── create_batched_ecdh_pkg ───────────────────────────────────────────────

    #[test]
    fn create_batched_ecdh_pkg_multiple_keys() {
        let secrets = [s32(S0), s32(S1)];
        let pkg = generate_dealer_package(2, 3, &secrets).unwrap();
        let (_, demo_pk1) = demo_keypair();
        // Second key: use share[1]'s pubkey as a target
        let demo_pk2 = pkg.group.members[1].pubkey;
        let members = [1u32, 3u32];

        let ecdh =
            create_batched_ecdh_pkg(&members, &[demo_pk1, demo_pk2], &pkg.shares[0]).unwrap();
        assert_eq!(ecdh.entries.len(), 2);
        assert_eq!(ecdh.entries[0].ecdh_pk, demo_pk1);
        assert_eq!(ecdh.entries[1].ecdh_pk, demo_pk2);
    }

    #[test]
    fn create_batched_ecdh_pkg_empty_keys() {
        let secrets = [s32(S0), s32(S1)];
        let pkg = generate_dealer_package(2, 3, &secrets).unwrap();
        let members = [1u32, 3u32];
        let ecdh = create_batched_ecdh_pkg(&members, &[], &pkg.shares[0]).unwrap();
        assert!(ecdh.entries.is_empty());
    }

    // ── combine_ecdh_pkgs ─────────────────────────────────────────────────────

    #[test]
    fn combine_ecdh_pkgs_matches_master_secret() {
        let secrets = [s32(S0), s32(S1)];
        let pkg = generate_dealer_package(2, 3, &secrets).unwrap();
        let (demo_sk, demo_pk) = demo_keypair();
        let members = [1u32, 3u32];

        let ecdh1 = create_ecdh_pkg(&members, &demo_pk, &pkg.shares[0]).unwrap();
        let ecdh3 = create_ecdh_pkg(&members, &demo_pk, &pkg.shares[2]).unwrap();

        let frost_secret = combine_ecdh_pkgs(&[ecdh1, ecdh3], &demo_pk).unwrap();

        // master_shared_secret = group_pk * demo_sk = tweak_pubkey(demo_pk, group_secret)
        let master_secret = crate::helpers::tweak_pubkey(&demo_pk, &s32(S0)).unwrap();
        assert_eq!(frost_secret, master_secret);
    }

    #[test]
    fn combine_ecdh_pkgs_matches_fixture() {
        let ecdh1 = EcdhPackage {
            idx: 1,
            members: vec![1, 3],
            entries: vec![EcdhEntry {
                ecdh_pk: p33("02ebd8227a6d7a03a98a1f86271d0687a6b6570187c37b39d21158a7d7835ba450"),
                keyshare: p33("0386c5b0f4bace78ef17d02b09e339b5a39f659dbbf1f3f531b9825df6836cfea9"),
            }],
        };
        let ecdh3 = EcdhPackage {
            idx: 3,
            members: vec![1, 3],
            entries: vec![EcdhEntry {
                ecdh_pk: p33("02ebd8227a6d7a03a98a1f86271d0687a6b6570187c37b39d21158a7d7835ba450"),
                keyshare: p33("023edaf055945d35006e1c52dd7a388e0c10b36eb55aa9d117853af87903cb54c0"),
            }],
        };
        let demo_pk = p33("02ebd8227a6d7a03a98a1f86271d0687a6b6570187c37b39d21158a7d7835ba450");
        let secret = combine_ecdh_pkgs(&[ecdh1, ecdh3], &demo_pk).unwrap();
        assert_eq!(
            hex::encode(secret),
            "020b6417cef5530ed4b82681945d4565ea7027f423a97b60247d07386ca3619585"
        );
    }

    #[test]
    fn combine_ecdh_pkgs_missing_entry_errors() {
        let secrets = [s32(S0), s32(S1)];
        let pkg = generate_dealer_package(2, 3, &secrets).unwrap();
        let (_, demo_pk) = demo_keypair();
        let wrong_pk = pkg.group.members[0].pubkey; // different key
        let members = [1u32, 3u32];

        let ecdh1 = create_ecdh_pkg(&members, &demo_pk, &pkg.shares[0]).unwrap();
        let ecdh3 = create_ecdh_pkg(&members, &demo_pk, &pkg.shares[2]).unwrap();

        // Ask for a key that's not in the packages
        let result = combine_ecdh_pkgs(&[ecdh1, ecdh3], &wrong_pk);
        assert!(result.is_err());
    }

    // ── combine_batched_ecdh_pkgs ─────────────────────────────────────────────

    #[test]
    fn combine_batched_ecdh_pkgs_all_keys() {
        let secrets = [s32(S0), s32(S1)];
        let pkg = generate_dealer_package(2, 3, &secrets).unwrap();
        let (_, demo_pk1) = demo_keypair();
        let demo_pk2 = pkg.group.members[1].pubkey;
        let members = [1u32, 3u32];

        let batch1 =
            create_batched_ecdh_pkg(&members, &[demo_pk1, demo_pk2], &pkg.shares[0]).unwrap();
        let batch3 =
            create_batched_ecdh_pkg(&members, &[demo_pk1, demo_pk2], &pkg.shares[2]).unwrap();

        let results = combine_batched_ecdh_pkgs(&[batch1, batch3]).unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].0, demo_pk1);
        assert_eq!(results[1].0, demo_pk2);
    }

    #[test]
    fn combine_batched_ecdh_pkgs_empty_input() {
        let results = combine_batched_ecdh_pkgs(&[]).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn combine_batched_matches_single_combine() {
        let secrets = [s32(S0), s32(S1)];
        let pkg = generate_dealer_package(2, 3, &secrets).unwrap();
        let (_, demo_pk) = demo_keypair();
        let members = [1u32, 3u32];

        let ecdh1_single = create_ecdh_pkg(&members, &demo_pk, &pkg.shares[0]).unwrap();
        let ecdh3_single = create_ecdh_pkg(&members, &demo_pk, &pkg.shares[2]).unwrap();
        let single_secret = combine_ecdh_pkgs(&[ecdh1_single, ecdh3_single], &demo_pk).unwrap();

        let batch1 = create_batched_ecdh_pkg(&members, &[demo_pk], &pkg.shares[0]).unwrap();
        let batch3 = create_batched_ecdh_pkg(&members, &[demo_pk], &pkg.shares[2]).unwrap();
        let batched = combine_batched_ecdh_pkgs(&[batch1, batch3]).unwrap();

        assert_eq!(batched[0].1, single_secret);
    }
}

#[cfg(test)]
mod dkg_tests {
    use crate::frost::dkg::*;
    use crate::frost::types::*;
    use crate::shares::derive_shares_secret;
    use crate::types::SecretShare;

    fn s32(hex: &str) -> [u8; 32] {
        hex::decode(hex).unwrap().try_into().unwrap()
    }

    fn seeds_for(seed: [&str; 2]) -> Vec<[u8; 32]> {
        seed.iter().map(|s| s32(s)).collect()
    }

    // Deterministic seeds for 3 participants, threshold 2.
    // Two seeds per participant so both polynomial coefficients are fixed.
    // Vectors verified against the cmdruid/frost TypeScript reference.
    const SEED1: [&str; 2] = [
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "1111111111111111111111111111111111111111111111111111111111111111",
    ];
    const SEED2: [&str; 2] = [
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "2222222222222222222222222222222222222222222222222222222222222222",
    ];
    const SEED3: [&str; 2] = [
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        "3333333333333333333333333333333333333333333333333333333333333333",
    ];

    const GROUP_PK: &str = "033079898bb4e1f96e993da9960c411002c28e3d2c82adbda66effac39f4be050e";

    // Expected aggregate shares per participant
    const AGG1: &str = "9999999999999999999999999999999c243bdfcc3b08592219f4dc7ff92d1715";
    const AGG2: &str = "00000000000000000000000000000003cff3694bf2261f4cc088e4598f5d3c3a";
    const AGG3: &str = "6666666666666666666666666666666a3659cfb2588c85b326ef4abff5c3a2a0";

    // Expected group secret recoverable from any 2-of-3 aggregate shares
    const GROUP_SECRET: &str = "33333333333333333333333333333335bdd57965d4a1f2bbb38e761992c6b0af";

    /// Run the full 3-participant DKG and return each participant's output.
    fn run_dkg() -> [DkgOutput; 3] {
        let seeds = [seeds_for(SEED1), seeds_for(SEED2), seeds_for(SEED3)];

        // Round 1
        let round1: Vec<(Vec<[u8; 32]>, DkgCommitPackage)> = (1u32..=3)
            .zip(seeds.iter())
            .map(|(idx, s)| dkg_round1(idx, 2, s))
            .collect();

        let all_commits: Vec<DkgCommitPackage> = round1.iter().map(|(_, c)| c.clone()).collect();

        // Round 2: each participant generates shares for all others
        let all_shares: Vec<DkgSharePackage> = round1
            .iter()
            .flat_map(|(coeffs, commit)| {
                (1u32..=3).map(move |recipient| dkg_round2(commit.idx, coeffs, recipient).unwrap())
            })
            .collect();

        // Finalize each participant
        std::array::from_fn(|i| {
            let my_idx = (i + 1) as u32;
            let (my_coeffs, _) = &round1[i];
            let received: Vec<DkgSharePackage> = all_shares
                .iter()
                .filter(|s| s.recipient_idx == my_idx && s.sender_idx != my_idx)
                .cloned()
                .collect();
            dkg_finalize(my_idx, my_coeffs, &received, &all_commits, 2).unwrap()
        })
    }

    // ── dkg_round1 ────────────────────────────────────────────────────────────

    #[test]
    fn round1_produces_correct_commit_count() {
        let (_, commit) = dkg_round1(1, 2, &seeds_for(SEED1));
        assert_eq!(commit.idx, 1);
        assert_eq!(commit.vss_commits.len(), 2); // threshold = 2
    }

    #[test]
    fn round1_produces_correct_coeff_count() {
        let (coeffs, _) = dkg_round1(1, 2, &seeds_for(SEED1));
        assert_eq!(coeffs.len(), 2);
    }

    #[test]
    fn round1_is_deterministic_with_seeds() {
        let (c1, pkg1) = dkg_round1(1, 2, &seeds_for(SEED1));
        let (c2, pkg2) = dkg_round1(1, 2, &seeds_for(SEED1));
        assert_eq!(c1, c2);
        assert_eq!(pkg1.vss_commits, pkg2.vss_commits);
    }

    #[test]
    fn round1_is_random_without_seeds() {
        let (_, pkg1) = dkg_round1(1, 2, &[]);
        let (_, pkg2) = dkg_round1(1, 2, &[]);
        assert_ne!(pkg1.vss_commits, pkg2.vss_commits);
    }

    #[test]
    fn round1_commits_match_fixture() {
        let (_, commit) = dkg_round1(1, 2, &seeds_for(SEED1));
        assert_eq!(
            hex::encode(commit.vss_commits[0]),
            "026a04ab98d9e4774ad806e302dddeb63bea16b5cb5f223ee77478e861bb583eb3"
        );
        assert_eq!(
            hex::encode(commit.vss_commits[1]),
            "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa"
        );
    }

    // ── dkg_round2 ────────────────────────────────────────────────────────────

    #[test]
    fn round2_share_matches_fixture() {
        let (coeffs, _) = dkg_round1(1, 2, &seeds_for(SEED1));
        let share = dkg_round2(1, &coeffs, 2).unwrap();
        assert_eq!(share.sender_idx, 1);
        assert_eq!(share.recipient_idx, 2);
        assert_eq!(
            hex::encode(share.seckey),
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
        );
    }

    #[test]
    fn round2_all_shares_match_fixture() {
        // All 9 shares (3 senders × 3 recipients) verified against TS reference.
        let expected: &[(u32, u32, &str)] = &[
            (
                1,
                1,
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            ),
            (
                1,
                2,
                "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            ),
            (
                1,
                3,
                "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            ),
            (
                2,
                1,
                "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            ),
            (
                2,
                2,
                "000000000000000000000000000000014551231950b75fc4402da1732fc9bebe",
            ),
            (
                2,
                3,
                "222222222222222222222222222222236773453b72d981e6624fc39551ebe0e0",
            ),
            (
                3,
                1,
                "000000000000000000000000000000014551231950b75fc4402da1732fc9bebe",
            ),
            (
                3,
                2,
                "333333333333333333333333333333347884564c83ea92f77360d4a662fcf1f1",
            ),
            (
                3,
                3,
                "66666666666666666666666666666667abb7897fb71dc62aa69407d996302524",
            ),
        ];
        let participant_seeds = [
            (1u32, seeds_for(SEED1)),
            (2u32, seeds_for(SEED2)),
            (3u32, seeds_for(SEED3)),
        ];
        for (sender_idx, seeds) in &participant_seeds {
            let (coeffs, _) = dkg_round1(*sender_idx, 2, seeds);
            for recipient_idx in 1u32..=3 {
                let share = dkg_round2(*sender_idx, &coeffs, recipient_idx).unwrap();
                let (_, _, expected_seckey) = expected
                    .iter()
                    .find(|(s, r, _)| *s == *sender_idx && *r == recipient_idx)
                    .unwrap();
                assert_eq!(
                    hex::encode(share.seckey),
                    *expected_seckey,
                    "share {sender_idx}→{recipient_idx} mismatch"
                );
            }
        }
    }

    // ── verify_dkg_share ──────────────────────────────────────────────────────

    #[test]
    fn verify_dkg_share_valid() {
        let (coeffs, commit) = dkg_round1(1, 2, &seeds_for(SEED1));
        for recipient in 1u32..=3 {
            let share = dkg_round2(1, &coeffs, recipient).unwrap();
            assert!(
                verify_dkg_share(&share, &commit, 2).unwrap(),
                "share 1→{recipient} should verify"
            );
        }
    }

    #[test]
    fn verify_dkg_share_tampered_seckey_fails() {
        let (coeffs, commit) = dkg_round1(1, 2, &seeds_for(SEED1));
        let mut share = dkg_round2(1, &coeffs, 2).unwrap();
        share.seckey[0] ^= 0xff;
        assert!(!verify_dkg_share(&share, &commit, 2).unwrap());
    }

    #[test]
    fn verify_dkg_share_wrong_commits_fails() {
        let (coeffs1, _) = dkg_round1(1, 2, &seeds_for(SEED1));
        let (_, commit2) = dkg_round1(2, 2, &seeds_for(SEED2));
        let share = dkg_round2(1, &coeffs1, 2).unwrap();
        // Verify share from participant 1 against participant 2's commits — should fail
        assert!(!verify_dkg_share(&share, &commit2, 2).unwrap());
    }

    // ── dkg_finalize ──────────────────────────────────────────────────────────

    #[test]
    fn finalize_group_pk_matches_fixture() {
        let outputs = run_dkg();
        for output in &outputs {
            assert_eq!(
                hex::encode(output.group.group_pk),
                GROUP_PK,
                "participant {} group_pk mismatch",
                output.share.idx
            );
        }
    }

    #[test]
    fn finalize_all_participants_agree_on_group_pk() {
        let outputs = run_dkg();
        let first_pk = outputs[0].group.group_pk;
        for output in &outputs[1..] {
            assert_eq!(output.group.group_pk, first_pk);
        }
    }

    #[test]
    fn finalize_aggregate_shares_match_fixture() {
        let outputs = run_dkg();
        assert_eq!(hex::encode(outputs[0].share.seckey), AGG1);
        assert_eq!(hex::encode(outputs[1].share.seckey), AGG2);
        assert_eq!(hex::encode(outputs[2].share.seckey), AGG3);
    }

    #[test]
    fn finalize_threshold_subsets_recover_secret() {
        let outputs = run_dkg();
        let to_low = |o: &DkgOutput| SecretShare {
            idx: o.share.idx,
            seckey: o.share.seckey,
        };

        // All three 2-of-3 subsets should recover the same secret
        let s12 = derive_shares_secret(&[to_low(&outputs[0]), to_low(&outputs[1])]).unwrap();
        let s13 = derive_shares_secret(&[to_low(&outputs[0]), to_low(&outputs[2])]).unwrap();
        let s23 = derive_shares_secret(&[to_low(&outputs[1]), to_low(&outputs[2])]).unwrap();

        assert_eq!(hex::encode(s12), GROUP_SECRET);
        assert_eq!(hex::encode(s13), GROUP_SECRET);
        assert_eq!(hex::encode(s23), GROUP_SECRET);
    }

    #[test]
    fn finalize_recovered_secret_matches_group_pk() {
        let outputs = run_dkg();
        let to_low = |o: &DkgOutput| SecretShare {
            idx: o.share.idx,
            seckey: o.share.seckey,
        };
        let secret = derive_shares_secret(&[to_low(&outputs[0]), to_low(&outputs[1])]).unwrap();
        let pk = crate::helpers::get_pubkey(&secret);
        assert_eq!(pk, outputs[0].group.group_pk);
    }

    #[test]
    fn finalize_member_identity_pks_are_first_vss_commits() {
        let outputs = run_dkg();
        let (_, commit1) = dkg_round1(1, 2, &seeds_for(SEED1));
        let (_, commit2) = dkg_round1(2, 2, &seeds_for(SEED2));
        let (_, commit3) = dkg_round1(3, 2, &seeds_for(SEED3));

        let group = &outputs[0].group;
        assert_eq!(group.members[0].identity_pk, Some(commit1.vss_commits[0]));
        assert_eq!(group.members[1].identity_pk, Some(commit2.vss_commits[0]));
        assert_eq!(group.members[2].identity_pk, Some(commit3.vss_commits[0]));
    }

    #[test]
    fn finalize_member_pubkeys_are_share_pubkeys() {
        let outputs = run_dkg();
        // Each member's pubkey must equal their aggregate share seckey * G.
        // We can verify this for our own slot (where we know the secret),
        // and for all slots via the VSS equation.
        for output in &outputs {
            let expected_pk = crate::helpers::get_pubkey(&output.share.seckey);
            let member = output
                .group
                .members
                .iter()
                .find(|m| m.idx == output.share.idx)
                .unwrap();
            assert_eq!(
                member.pubkey, expected_pk,
                "member {} pubkey should equal share pubkey",
                output.share.idx
            );
        }
    }

    #[test]
    fn finalize_dealer_members_have_no_identity_pk() {
        let secrets = [
            hex::decode("0070ca75929ca1ec4cd70ac34f46079bdfdd87f9d0c0bf4275f3882f7b462d0f")
                .unwrap()
                .try_into()
                .unwrap(),
            hex::decode("0e0376a7180253cdb8b6020bff0eda529760da65e715663e2152e4be2fc7b443")
                .unwrap()
                .try_into()
                .unwrap(),
        ];
        let pkg = crate::frost::dealer::generate_dealer_package(2, 3, &secrets).unwrap();
        for member in &pkg.group.members {
            assert_eq!(member.identity_pk, None);
        }
    }

    #[test]
    fn finalize_threshold_is_set_correctly() {
        let outputs = run_dkg();
        for output in &outputs {
            assert_eq!(output.group.threshold, 2);
        }
    }

    #[test]
    fn finalize_vss_commits_verify_aggregate_shares() {
        let outputs = run_dkg();
        for output in &outputs {
            let low_share = SecretShare {
                idx: output.share.idx,
                seckey: output.share.seckey,
            };
            let valid = crate::shares::verify_share(
                &output.vss_commits,
                &low_share,
                output.group.threshold,
            )
            .unwrap();
            assert!(
                valid,
                "aggregate share for participant {} failed VSS verification",
                output.share.idx
            );
        }
    }

    #[test]
    fn finalize_rejects_tampered_share() {
        let seeds = [seeds_for(SEED1), seeds_for(SEED2), seeds_for(SEED3)];
        let round1: Vec<(Vec<[u8; 32]>, DkgCommitPackage)> = (1u32..=3)
            .zip(seeds.iter())
            .map(|(idx, s)| dkg_round1(idx, 2, s))
            .collect();
        let all_commits: Vec<DkgCommitPackage> = round1.iter().map(|(_, c)| c.clone()).collect();

        // Build shares for participant 1, but tamper with one
        let mut received: Vec<DkgSharePackage> = round1
            .iter()
            .filter(|(_, c)| c.idx != 1)
            .map(|(coeffs, commit)| dkg_round2(commit.idx, coeffs, 1).unwrap())
            .collect();
        received[0].seckey[0] ^= 0xff; // tamper

        let result = dkg_finalize(1, &round1[0].0, &received, &all_commits, 2);
        assert!(result.is_err());
    }

    #[test]
    fn finalize_rejects_unknown_sender() {
        let seeds = [seeds_for(SEED1), seeds_for(SEED2)];
        let round1: Vec<(Vec<[u8; 32]>, DkgCommitPackage)> = (1u32..=2)
            .zip(seeds.iter())
            .map(|(idx, s)| dkg_round1(idx, 2, s))
            .collect();
        let all_commits: Vec<DkgCommitPackage> = round1.iter().map(|(_, c)| c.clone()).collect();

        // A share from a sender (idx=99) not in all_commits
        let ghost_share = DkgSharePackage {
            sender_idx: 99,
            recipient_idx: 1,
            seckey: [0u8; 32],
        };

        let result = dkg_finalize(1, &round1[0].0, &[ghost_share], &all_commits, 2);
        assert!(result.is_err());
    }

    // ── end-to-end: DKG output is usable for signing ──────────────────────────

    #[test]
    fn dkg_output_can_sign() {
        use crate::frost::nonce::{derive_secret_nonce, generate_nonce_pair, to_member_nonce};
        use crate::frost::signing::{
            combine_signatures, create_partial_sig_package, create_sign_session,
        };
        use crate::frost::types::MemberNonce;

        let outputs = run_dkg();

        // Use participants 1 and 2 to sign
        let signers = &outputs[..2];
        let message = b"hello from dkg";

        let nonce_pairs: Vec<_> = signers
            .iter()
            .map(|o| generate_nonce_pair(&o.share.seckey))
            .collect();

        let member_nonces: Vec<MemberNonce> = signers
            .iter()
            .zip(nonce_pairs.iter())
            .map(|(o, n)| to_member_nonce(n.clone(), o.share.idx))
            .collect();

        let secret_nonces: Vec<_> = signers
            .iter()
            .zip(nonce_pairs.iter())
            .map(|(o, n)| derive_secret_nonce(&o.share.seckey, &n.code))
            .collect();

        let session = create_sign_session(
            &outputs[0].group,
            signers.iter().map(|o| o.share.idx).collect(),
            vec![(message.to_vec(), vec![])],
            member_nonces,
        )
        .unwrap();

        let psig1 =
            create_partial_sig_package(&session, &signers[0].share, &secret_nonces[0]).unwrap();
        let psig2 =
            create_partial_sig_package(&session, &signers[1].share, &secret_nonces[1]).unwrap();

        let sigs = combine_signatures(&session, &outputs[0].group, &[psig1, psig2]).unwrap();
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].message, message);
        // Signature is 64 bytes and was verified internally by combine_signatures
        assert_eq!(sigs[0].sig.len(), 64);
    }
}
