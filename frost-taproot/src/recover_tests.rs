#[cfg(test)]
mod recover_tests {
    use crate::group::create_dealer_set;
    use crate::recover::*;
    use crate::types::SecretShare;

    fn s32(hex: &str) -> [u8; 32] {
        hex::decode(hex).unwrap().try_into().unwrap()
    }

    const S0: &str = "0070ca75929ca1ec4cd70ac34f46079bdfdd87f9d0c0bf4275f3882f7b462d0f";
    const S1: &str = "0e0376a7180253cdb8b6020bff0eda529760da65e715663e2152e4be2fc7b443";

    // ── gen_recovery_shares ──────────────────────────────────────────────────

    #[test]
    fn gen_recovery_shares_correct_structure() {
        let secrets = [s32(S0), s32(S1)];
        let group = create_dealer_set(2, 3, &secrets).unwrap();
        let members = [2u32, 3u32];
        let pkg = gen_recovery_shares(&members, &group.shares[1], 1, 2, &[]).unwrap();
        assert_eq!(pkg.idx, 2); // originating share's idx
        assert_eq!(pkg.shares.len(), 2); // one per member
                                         // vss_commits = rand_coeffs (threshold-1) + repair_coeff = threshold total
        assert_eq!(pkg.vss_commits.len(), 2);
    }

    #[test]
    fn gen_recovery_shares_not_enough_members_errors() {
        let secrets = [s32(S0), s32(S1)];
        let group = create_dealer_set(2, 3, &secrets).unwrap();
        // Only 1 member but threshold=2
        assert!(gen_recovery_shares(&[2u32], &group.shares[1], 1, 2, &[]).is_err());
    }

    // ── recover_share ────────────────────────────────────────────────────────

    #[test]
    fn recover_share_reconstructs_lost_share() {
        // Members 2 and 3 help recover share for target=1.
        // Protocol: each helper generates recovery shares, then target sums
        // the aggregated shares it receives.
        let secrets = [s32(S0), s32(S1)];
        let group = create_dealer_set(2, 3, &secrets).unwrap();
        let members = [2u32, 3u32];

        let pkg2 = gen_recovery_shares(&members, &group.shares[1], 1, 2, &[s32(S0)]).unwrap();
        let pkg3 = gen_recovery_shares(&members, &group.shares[2], 1, 2, &[s32(S1)]).unwrap();

        // Each member aggregates the shares they received from others at their own index.
        // Member 2 receives: pkg2.shares[idx=2] + pkg3.shares[idx=2]
        // Member 3 receives: pkg2.shares[idx=3] + pkg3.shares[idx=3]
        use crate::ecc::util::{scalar_from_bytes, scalar_to_bytes};

        let agg2 = {
            let a = scalar_from_bytes(&pkg2.shares.iter().find(|s| s.idx == 2).unwrap().seckey);
            let b = scalar_from_bytes(&pkg3.shares.iter().find(|s| s.idx == 2).unwrap().seckey);
            SecretShare {
                idx: 2,
                seckey: scalar_to_bytes(&(a + b)),
            }
        };
        let agg3 = {
            let a = scalar_from_bytes(&pkg2.shares.iter().find(|s| s.idx == 3).unwrap().seckey);
            let b = scalar_from_bytes(&pkg3.shares.iter().find(|s| s.idx == 3).unwrap().seckey);
            SecretShare {
                idx: 3,
                seckey: scalar_to_bytes(&(a + b)),
            }
        };

        let repaired = recover_share(&[agg2, agg3], 1);
        assert_eq!(repaired.idx, 1);
        assert_eq!(
            hex::encode(repaired.seckey),
            hex::encode(group.shares[0].seckey),
            "recovered share must match original"
        );
    }

    #[test]
    fn recover_share_sums_scalars() {
        // recover_share simply sums the provided shares.
        let a = SecretShare {
            idx: 1,
            seckey: s32("0000000000000000000000000000000000000000000000000000000000000003"),
        };
        let b = SecretShare {
            idx: 1,
            seckey: s32("0000000000000000000000000000000000000000000000000000000000000004"),
        };
        let result = recover_share(&[a, b], 5);
        assert_eq!(result.idx, 5);
        assert_eq!(result.seckey[31], 7);
    }

    #[test]
    fn recover_share_single_input() {
        let a = SecretShare {
            idx: 2,
            seckey: s32("0e74411caa9ef5ba058d0ccf4e54e1ee773e625fb7d6258097466cedab0de152"),
        };
        let result = recover_share(&[a.clone()], 2);
        assert_eq!(result.seckey, a.seckey);
    }
}
