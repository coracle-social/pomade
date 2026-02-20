#[cfg(test)]
mod shares_tests {
    use crate::ecc::util::scalar_from_bytes;
    use crate::shares::*;
    use crate::types::SecretShare;
    use crate::vss::create_share_coeffs;

    fn s32(hex: &str) -> [u8; 32] {
        hex::decode(hex).unwrap().try_into().unwrap()
    }

    fn share(idx: u32, seckey_hex: &str) -> SecretShare {
        SecretShare {
            idx,
            seckey: s32(seckey_hex),
        }
    }

    // ── create_shares ────────────────────────────────────────────────────────

    #[test]
    fn create_shares_count_and_indices() {
        let s0 = s32("0070ca75929ca1ec4cd70ac34f46079bdfdd87f9d0c0bf4275f3882f7b462d0f");
        let s1 = s32("0e0376a7180253cdb8b6020bff0eda529760da65e715663e2152e4be2fc7b443");
        let coeffs = create_share_coeffs(&[s0, s1], 2);
        let shares = create_shares(&coeffs, 3).unwrap();
        assert_eq!(shares.len(), 3);
        assert_eq!(shares[0].idx, 1);
        assert_eq!(shares[1].idx, 2);
        assert_eq!(shares[2].idx, 3);
    }

    #[test]
    fn create_shares_matches_fixture() {
        let s0 = s32("0070ca75929ca1ec4cd70ac34f46079bdfdd87f9d0c0bf4275f3882f7b462d0f");
        let s1 = s32("0e0376a7180253cdb8b6020bff0eda529760da65e715663e2152e4be2fc7b443");
        let coeffs = create_share_coeffs(&[s0, s1], 2);
        let shares = create_shares(&coeffs, 3).unwrap();
        assert_eq!(
            hex::encode(shares[0].seckey),
            "0e74411caa9ef5ba058d0ccf4e54e1ee773e625fb7d6258097466cedab0de152"
        );
        assert_eq!(
            hex::encode(shares[1].seckey),
            "1c77b7c3c2a14987be430edb4d63bc410e9f3cc59eeb8bbeb89951abdad59595"
        );
        assert_eq!(
            hex::encode(shares[2].seckey),
            "2a7b2e6adaa39d5576f910e74c729693a600172b8600f1fcd9ec366a0a9d49d8"
        );
    }

    // ── combine_shares ───────────────────────────────────────────────────────

    #[test]
    fn combine_shares_sums_scalars() {
        let a = share(
            1,
            "0000000000000000000000000000000000000000000000000000000000000003",
        );
        let b = share(
            2,
            "0000000000000000000000000000000000000000000000000000000000000004",
        );
        let result = combine_shares(&[a, b]);
        let expected = scalar_from_bytes(&{
            let mut b = [0u8; 32];
            b[31] = 7;
            b
        });
        assert_eq!(scalar_from_bytes(&result), expected);
    }

    #[test]
    fn combine_shares_single() {
        let a = share(
            1,
            "0e74411caa9ef5ba058d0ccf4e54e1ee773e625fb7d6258097466cedab0de152",
        );
        let result = combine_shares(&[a.clone()]);
        assert_eq!(result, a.seckey);
    }

    // ── combine_set ──────────────────────────────────────────────────────────

    #[test]
    fn combine_set_same_idx() {
        let a = share(
            1,
            "0000000000000000000000000000000000000000000000000000000000000003",
        );
        let b = share(
            1,
            "0000000000000000000000000000000000000000000000000000000000000004",
        );
        let result = combine_set(&[a, b]).unwrap();
        assert_eq!(result.idx, 1);
        assert_eq!(result.seckey[31], 7);
    }

    #[test]
    fn combine_set_mismatched_idx_errors() {
        let a = share(
            1,
            "0000000000000000000000000000000000000000000000000000000000000003",
        );
        let b = share(
            2,
            "0000000000000000000000000000000000000000000000000000000000000004",
        );
        assert!(combine_set(&[a, b]).is_err());
    }

    // ── merge_shares ─────────────────────────────────────────────────────────

    #[test]
    fn merge_shares_combines_matching_indices() {
        let a1 = share(
            1,
            "0000000000000000000000000000000000000000000000000000000000000003",
        );
        let a2 = share(
            2,
            "0000000000000000000000000000000000000000000000000000000000000005",
        );
        let b1 = share(
            1,
            "0000000000000000000000000000000000000000000000000000000000000004",
        );
        let b2 = share(
            2,
            "0000000000000000000000000000000000000000000000000000000000000006",
        );
        let merged = merge_shares(&[a1, a2], &[b1, b2]).unwrap();
        assert_eq!(merged[0].idx, 1);
        assert_eq!(merged[0].seckey[31], 7);
        assert_eq!(merged[1].idx, 2);
        assert_eq!(merged[1].seckey[31], 11);
    }

    #[test]
    fn merge_shares_mismatched_lengths_errors() {
        let a = vec![share(
            1,
            "0000000000000000000000000000000000000000000000000000000000000001",
        )];
        let b: Vec<SecretShare> = vec![];
        assert!(merge_shares(&a, &b).is_err());
    }

    // ── verify_share ─────────────────────────────────────────────────────────

    #[test]
    fn verify_share_valid_shares() {
        let s0 = s32("0070ca75929ca1ec4cd70ac34f46079bdfdd87f9d0c0bf4275f3882f7b462d0f");
        let s1 = s32("0e0376a7180253cdb8b6020bff0eda529760da65e715663e2152e4be2fc7b443");
        let coeffs = create_share_coeffs(&[s0, s1], 2);
        let shares = create_shares(&coeffs, 3).unwrap();
        let commits: Vec<[u8; 33]> = crate::vss::get_share_commits(&coeffs);
        for s in &shares {
            assert!(
                verify_share(&commits, s, 2).unwrap(),
                "share {} should be valid",
                s.idx
            );
        }
    }

    #[test]
    fn verify_share_tampered_share_fails() {
        let s0 = s32("0070ca75929ca1ec4cd70ac34f46079bdfdd87f9d0c0bf4275f3882f7b462d0f");
        let s1 = s32("0e0376a7180253cdb8b6020bff0eda529760da65e715663e2152e4be2fc7b443");
        let coeffs = create_share_coeffs(&[s0, s1], 2);
        let mut shares = create_shares(&coeffs, 3).unwrap();
        let commits = crate::vss::get_share_commits(&coeffs);
        // Corrupt share[0]
        shares[0].seckey[0] ^= 0xff;
        assert!(!verify_share(&commits, &shares[0], 2).unwrap());
    }

    // ── derive_shares_secret ─────────────────────────────────────────────────

    #[test]
    fn derive_shares_secret_recovers_root() {
        let s0 = s32("0070ca75929ca1ec4cd70ac34f46079bdfdd87f9d0c0bf4275f3882f7b462d0f");
        let s1 = s32("0e0376a7180253cdb8b6020bff0eda529760da65e715663e2152e4be2fc7b443");
        let coeffs = create_share_coeffs(&[s0, s1], 2);
        let shares = create_shares(&coeffs, 3).unwrap();
        // Any 2-of-3 subset should recover s0
        let secret_12 = derive_shares_secret(&shares[..2]).unwrap();
        let secret_13 = derive_shares_secret(&[shares[0].clone(), shares[2].clone()]).unwrap();
        let secret_23 = derive_shares_secret(&shares[1..]).unwrap();
        assert_eq!(secret_12, s0);
        assert_eq!(secret_13, s0);
        assert_eq!(secret_23, s0);
    }

    #[test]
    fn derive_shares_secret_all_three_also_recovers() {
        let s0 = s32("0070ca75929ca1ec4cd70ac34f46079bdfdd87f9d0c0bf4275f3882f7b462d0f");
        let s1 = s32("0e0376a7180253cdb8b6020bff0eda529760da65e715663e2152e4be2fc7b443");
        let coeffs = create_share_coeffs(&[s0, s1], 2);
        let shares = create_shares(&coeffs, 3).unwrap();
        let secret = derive_shares_secret(&shares).unwrap();
        assert_eq!(secret, s0);
    }
}
