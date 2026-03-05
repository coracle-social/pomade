#[cfg(test)]
mod tests {
    use crate::group::create_dealer_set;
    use crate::refresh::*;
    use crate::shares::derive_shares_secret;
    use crate::types::SecretShare;

    fn s32(hex: &str) -> [u8; 32] {
        hex::decode(hex).unwrap().try_into().unwrap()
    }

    const S0: &str = "0070ca75929ca1ec4cd70ac34f46079bdfdd87f9d0c0bf4275f3882f7b462d0f";
    const S1: &str = "0e0376a7180253cdb8b6020bff0eda529760da65e715663e2152e4be2fc7b443";
    const R0: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const R1: &str = "2222222222222222222222222222222222222222222222222222222222222222";
    const R2: &str = "3333333333333333333333333333333333333333333333333333333333333333";

    // ── gen_refresh_shares ───────────────────────────────────────────────────

    #[test]
    fn gen_refresh_shares_correct_counts() {
        let pkg = gen_refresh_shares(1, 2, 3, &[s32(R0)]).unwrap();
        assert_eq!(pkg.shares.len(), 3);
        assert_eq!(pkg.vss_commits.len(), 1); // threshold - 1 = 1
        assert_eq!(pkg.idx, 1);
    }

    #[test]
    fn gen_refresh_shares_polynomial_has_zero_constant_term() {
        // The refresh polynomial f has f(0) = 0.
        // Verify: sum of all refresh shares from one participant, interpolated at 0, equals 0.
        use crate::ecc::util::scalar_from_bytes;
        use crate::poly::index_to_scalar;
        use crate::poly::interpolate_root;

        let pkg = gen_refresh_shares(1, 2, 3, &[s32(R0)]).unwrap();
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

    #[test]
    fn gen_refresh_shares_deterministic_with_secrets() {
        let a = gen_refresh_shares(1, 2, 3, &[s32(R0)]).unwrap();
        let b = gen_refresh_shares(1, 2, 3, &[s32(R0)]).unwrap();
        for (sa, sb) in a.shares.iter().zip(b.shares.iter()) {
            assert_eq!(sa.seckey, sb.seckey);
        }
    }

    // ── refresh_share ────────────────────────────────────────────────────────

    #[test]
    fn refresh_share_preserves_secret() {
        // Full 3-participant refresh: secret must be unchanged after refresh.
        let secrets = [s32(S0), s32(S1)];
        let group = create_dealer_set(2, 3, &secrets).unwrap();

        let rp1 = gen_refresh_shares(1, 2, 3, &[s32(R0)]).unwrap();
        let rp2 = gen_refresh_shares(2, 2, 3, &[s32(R1)]).unwrap();
        let rp3 = gen_refresh_shares(3, 2, 3, &[s32(R2)]).unwrap();

        // Each participant collects all refresh shares addressed to them (including own).
        let agg1: Vec<SecretShare> = [&rp1, &rp2, &rp3]
            .iter()
            .map(|pkg| pkg.shares.iter().find(|s| s.idx == 1).unwrap().clone())
            .collect();
        let agg2: Vec<SecretShare> = [&rp1, &rp2, &rp3]
            .iter()
            .map(|pkg| pkg.shares.iter().find(|s| s.idx == 2).unwrap().clone())
            .collect();

        let new1 = refresh_share(&agg1, &group.shares[0]).unwrap();
        let new2 = refresh_share(&agg2, &group.shares[1]).unwrap();

        let recovered = derive_shares_secret(&[new1, new2]).unwrap();
        assert_eq!(recovered, s32(S0), "secret must be unchanged after refresh");
    }

    #[test]
    fn refresh_share_changes_share_values() {
        let secrets = [s32(S0), s32(S1)];
        let group = create_dealer_set(2, 3, &secrets).unwrap();
        let rp1 = gen_refresh_shares(1, 2, 3, &[s32(R0)]).unwrap();
        let rp2 = gen_refresh_shares(2, 2, 3, &[s32(R1)]).unwrap();
        let rp3 = gen_refresh_shares(3, 2, 3, &[s32(R2)]).unwrap();

        let agg1: Vec<SecretShare> = [&rp1, &rp2, &rp3]
            .iter()
            .map(|pkg| pkg.shares.iter().find(|s| s.idx == 1).unwrap().clone())
            .collect();

        let new1 = refresh_share(&agg1, &group.shares[0]).unwrap();
        // The refreshed share should differ from the original
        assert_ne!(new1.seckey, group.shares[0].seckey);
        assert_eq!(new1.idx, group.shares[0].idx);
    }

    #[test]
    fn refresh_share_mismatched_idx_errors() {
        let current = SecretShare {
            idx: 1,
            seckey: s32("0e74411caa9ef5ba058d0ccf4e54e1ee773e625fb7d6258097466cedab0de152"),
        };
        let wrong_idx = SecretShare {
            idx: 2, // different idx
            seckey: s32("0000000000000000000000000000000000000000000000000000000000000001"),
        };
        // combine_set will fail because indices differ
        assert!(refresh_share(&[wrong_idx], &current).is_err());
    }
}
