#[cfg(test)]
mod vss_tests {
    use crate::ecc::group::{scalar_base_multi, serialize_element};
    use crate::ecc::util::scalar_from_bytes;
    use crate::vss::*;
    use k256::Scalar;

    fn s32(hex: &str) -> [u8; 32] {
        hex::decode(hex).unwrap().try_into().unwrap()
    }

    fn p33(hex: &str) -> [u8; 33] {
        hex::decode(hex).unwrap().try_into().unwrap()
    }

    // ── create_share_coeffs ──────────────────────────────────────────────────

    #[test]
    fn create_share_coeffs_uses_provided_secrets() {
        let s0 = s32("0070ca75929ca1ec4cd70ac34f46079bdfdd87f9d0c0bf4275f3882f7b462d0f");
        let s1 = s32("0e0376a7180253cdb8b6020bff0eda529760da65e715663e2152e4be2fc7b443");
        let coeffs = create_share_coeffs(&[s0, s1], 2);
        assert_eq!(coeffs.len(), 2);
        assert_eq!(coeffs[0], scalar_from_bytes(&s0));
        assert_eq!(coeffs[1], scalar_from_bytes(&s1));
    }

    #[test]
    fn create_share_coeffs_fills_random_when_short() {
        let s0 = s32("0070ca75929ca1ec4cd70ac34f46079bdfdd87f9d0c0bf4275f3882f7b462d0f");
        let coeffs = create_share_coeffs(&[s0], 3);
        assert_eq!(coeffs.len(), 3);
        // First coeff is deterministic
        assert_eq!(coeffs[0], scalar_from_bytes(&s0));
        // Remaining two are random (non-zero with overwhelming probability)
        // We can't assert their values, but we can check they're not zero
        assert_ne!(coeffs[1], Scalar::ZERO);
        assert_ne!(coeffs[2], Scalar::ZERO);
    }

    #[test]
    fn create_share_coeffs_empty_secrets_all_random() {
        let coeffs = create_share_coeffs(&[], 3);
        assert_eq!(coeffs.len(), 3);
    }

    #[test]
    fn create_share_coeffs_threshold_zero_is_empty() {
        let coeffs = create_share_coeffs(&[], 0);
        assert!(coeffs.is_empty());
    }

    // ── get_share_commits ────────────────────────────────────────────────────

    #[test]
    fn get_share_commits_matches_fixture() {
        let s0 = s32("0070ca75929ca1ec4cd70ac34f46079bdfdd87f9d0c0bf4275f3882f7b462d0f");
        let s1 = s32("0e0376a7180253cdb8b6020bff0eda529760da65e715663e2152e4be2fc7b443");
        let coeffs = create_share_coeffs(&[s0, s1], 2);
        let commits = get_share_commits(&coeffs);
        assert_eq!(commits.len(), 2);
        assert_eq!(
            hex::encode(commits[0]),
            "021ae63bc9ddaffe52d44c3018e83115bfb22195bd8112fcad112310714e6fd5ec"
        );
        assert_eq!(
            hex::encode(commits[1]),
            "024f75a5478deda1102eba931e19425e59c1750533a54218ce215ced343fbfb6cf"
        );
    }

    #[test]
    fn get_share_commits_commit_is_scalar_times_generator() {
        let s0 = s32("0070ca75929ca1ec4cd70ac34f46079bdfdd87f9d0c0bf4275f3882f7b462d0f");
        let coeffs = create_share_coeffs(&[s0], 1);
        let commits = get_share_commits(&coeffs);
        let expected = serialize_element(&scalar_base_multi(&coeffs[0]));
        assert_eq!(commits[0], expected);
    }

    // ── merge_share_commits ──────────────────────────────────────────────────

    #[test]
    fn merge_share_commits_adds_points() {
        let s0 = s32("0070ca75929ca1ec4cd70ac34f46079bdfdd87f9d0c0bf4275f3882f7b462d0f");
        let s1 = s32("0e0376a7180253cdb8b6020bff0eda529760da65e715663e2152e4be2fc7b443");
        let coeffs_a = create_share_coeffs(&[s0], 1);
        let coeffs_b = create_share_coeffs(&[s1], 1);
        let commits_a = get_share_commits(&coeffs_a);
        let commits_b = get_share_commits(&coeffs_b);
        let merged = merge_share_commits(&commits_a, &commits_b).unwrap();
        // merged[0] should be (s0 + s1) * G
        let combined = scalar_from_bytes(&s0) + scalar_from_bytes(&s1);
        let expected = serialize_element(&scalar_base_multi(&combined));
        assert_eq!(merged[0], expected);
    }

    #[test]
    fn merge_share_commits_mismatched_lengths_errors() {
        let a = vec![p33(
            "021ae63bc9ddaffe52d44c3018e83115bfb22195bd8112fcad112310714e6fd5ec",
        )];
        let b: Vec<[u8; 33]> = vec![];
        assert!(merge_share_commits(&a, &b).is_err());
    }
}
