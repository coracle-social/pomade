#[cfg(test)]
mod group_tests {
    use crate::group::*;
    use crate::shares::verify_share;

    fn s32(hex: &str) -> [u8; 32] {
        hex::decode(hex).unwrap().try_into().unwrap()
    }

    const S0: &str = "0070ca75929ca1ec4cd70ac34f46079bdfdd87f9d0c0bf4275f3882f7b462d0f";
    const S1: &str = "0e0376a7180253cdb8b6020bff0eda529760da65e715663e2152e4be2fc7b443";

    // ── create_share_set ─────────────────────────────────────────────────────

    #[test]
    fn create_share_set_correct_counts() {
        let secrets = [s32(S0), s32(S1)];
        let set = create_share_set(2, 3, &secrets).unwrap();
        assert_eq!(set.shares.len(), 3);
        assert_eq!(set.vss_commits.len(), 2);
    }

    #[test]
    fn create_share_set_shares_are_valid() {
        let secrets = [s32(S0), s32(S1)];
        let set = create_share_set(2, 3, &secrets).unwrap();
        for share in &set.shares {
            assert!(
                verify_share(&set.vss_commits, share, 2).unwrap(),
                "share {} should verify",
                share.idx
            );
        }
    }

    #[test]
    fn create_share_set_vss_commits_match_fixture() {
        let secrets = [s32(S0), s32(S1)];
        let set = create_share_set(2, 3, &secrets).unwrap();
        assert_eq!(
            hex::encode(set.vss_commits[0]),
            "021ae63bc9ddaffe52d44c3018e83115bfb22195bd8112fcad112310714e6fd5ec"
        );
        assert_eq!(
            hex::encode(set.vss_commits[1]),
            "024f75a5478deda1102eba931e19425e59c1750533a54218ce215ced343fbfb6cf"
        );
    }

    // ── create_dealer_set ────────────────────────────────────────────────────

    #[test]
    fn create_dealer_set_group_pk_is_first_commit() {
        let secrets = [s32(S0), s32(S1)];
        let set = create_dealer_set(2, 3, &secrets).unwrap();
        assert_eq!(set.group_pk, set.vss_commits[0]);
    }

    #[test]
    fn create_dealer_set_group_pk_matches_fixture() {
        let secrets = [s32(S0), s32(S1)];
        let set = create_dealer_set(2, 3, &secrets).unwrap();
        assert_eq!(
            hex::encode(set.group_pk),
            "021ae63bc9ddaffe52d44c3018e83115bfb22195bd8112fcad112310714e6fd5ec"
        );
    }

    #[test]
    fn create_dealer_set_shares_match_fixture() {
        let secrets = [s32(S0), s32(S1)];
        let set = create_dealer_set(2, 3, &secrets).unwrap();
        assert_eq!(
            hex::encode(set.shares[0].seckey),
            "0e74411caa9ef5ba058d0ccf4e54e1ee773e625fb7d6258097466cedab0de152"
        );
        assert_eq!(
            hex::encode(set.shares[1].seckey),
            "1c77b7c3c2a14987be430edb4d63bc410e9f3cc59eeb8bbeb89951abdad59595"
        );
        assert_eq!(
            hex::encode(set.shares[2].seckey),
            "2a7b2e6adaa39d5576f910e74c729693a600172b8600f1fcd9ec366a0a9d49d8"
        );
    }

    #[test]
    fn create_dealer_set_no_secrets_is_random() {
        let a = create_dealer_set(2, 3, &[]).unwrap();
        let b = create_dealer_set(2, 3, &[]).unwrap();
        // Random secrets → different group keys
        assert_ne!(a.group_pk, b.group_pk);
    }
}
