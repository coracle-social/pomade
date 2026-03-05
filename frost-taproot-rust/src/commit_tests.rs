#[cfg(test)]
mod tests {
    use crate::commit::*;
    use crate::ecc::group::{scalar_base_multi, serialize_element};
    use crate::ecc::util::scalar_from_bytes;
    use crate::types::{BindFactor, PublicNonce, SecretShare};

    fn s32(hex: &str) -> [u8; 32] {
        hex::decode(hex).unwrap().try_into().unwrap()
    }
    fn p33(hex: &str) -> [u8; 33] {
        hex::decode(hex).unwrap().try_into().unwrap()
    }

    fn fixture_nonces() -> Vec<PublicNonce> {
        vec![
            PublicNonce {
                idx: 1,
                hidden_pn: p33(
                    "024d837d707dfa4b56be26da22b9ff5cb0fd220d011351ba79334003f16871801c",
                ),
                binder_pn: p33(
                    "0263c0d31a58799213f5210685b8bc2ce4539819a90c09c216a983e8f8c67a12f5",
                ),
            },
            PublicNonce {
                idx: 2,
                hidden_pn: p33(
                    "034bc9f2ef5cc5eb741cc00d763e1077e8bc624df82d198781c71a0757617d8d44",
                ),
                binder_pn: p33(
                    "03a1e7d63fd0665b9255df5f6d781762f7e7298a2c42ee6d67cfd287780fb3c2a6",
                ),
            },
        ]
    }

    const GROUP_PK: &str = "021ae63bc9ddaffe52d44c3018e83115bfb22195bd8112fcad112310714e6fd5ec";
    const TWEAKED_GROUP_PK: &str =
        "025731d4d57552d12877e3db13061d7f6ca09198963e003d1d6e0960d6651e42d3";
    const MESSAGE: &str = "68656c6c6f20776f726c6421";

    // ── get_nonce_ids ─────────────────────────────────────────────────────────

    #[test]
    fn get_nonce_ids_extracts_ids() {
        let ids = get_nonce_ids(&fixture_nonces());
        assert_eq!(ids, vec![1u32, 2u32]);
    }

    #[test]
    fn get_nonce_ids_empty_slice() {
        assert!(get_nonce_ids(&[]).is_empty());
    }

    // ── get_commits_prefix ────────────────────────────────────────────────────

    #[test]
    fn get_commits_prefix_sorts_by_id() {
        let nonces = fixture_nonces();
        let reversed = vec![nonces[1].clone(), nonces[0].clone()];
        assert_eq!(get_commits_prefix(&nonces), get_commits_prefix(&reversed));
    }

    #[test]
    fn get_commits_prefix_correct_length() {
        let prefix = get_commits_prefix(&fixture_nonces());
        // 2 participants × (32 + 33 + 33) = 196 bytes
        assert_eq!(prefix.len(), 2 * (32 + 33 + 33));
    }

    // ── get_group_prefix ──────────────────────────────────────────────────────

    #[test]
    fn get_group_prefix_starts_with_group_pk() {
        let group_pk = p33(GROUP_PK);
        let msg = hex::decode(MESSAGE).unwrap();
        let prefix = get_group_prefix(&fixture_nonces(), &group_pk, &msg);
        assert_eq!(&prefix[..33], &group_pk);
    }

    #[test]
    fn get_group_prefix_correct_length() {
        let group_pk = p33(GROUP_PK);
        let msg = hex::decode(MESSAGE).unwrap();
        let prefix = get_group_prefix(&fixture_nonces(), &group_pk, &msg);
        // 33 + 32 + 32 = 97
        assert_eq!(prefix.len(), 97);
    }

    #[test]
    fn get_group_prefix_differs_for_different_messages() {
        let group_pk = p33(GROUP_PK);
        let p1 = get_group_prefix(&fixture_nonces(), &group_pk, b"msg1");
        let p2 = get_group_prefix(&fixture_nonces(), &group_pk, b"msg2");
        assert_ne!(p1, p2);
    }

    #[test]
    fn get_group_prefix_matches_fixture() {
        let group_pk = p33(TWEAKED_GROUP_PK);
        let msg = hex::decode(MESSAGE).unwrap();
        let prefix = get_group_prefix(&fixture_nonces(), &group_pk, &msg);
        let want = "025731d4d57552d12877e3db13061d7f6ca09198963e003d1d6e0960d6651e42d3\
                    c00982b3526dcd6b7bcb4f685ddb41c7d00fecd032aa479f5df03601701bf5232\
                    ba4662301918443c019abba4a752cdcb8d4f572ad78a88ec416f17b60bb866c";
        assert_eq!(hex::encode(&prefix), want.replace('\n', ""));
    }

    // ── get_bind_factor ───────────────────────────────────────────────────────

    #[test]
    fn get_bind_factor_finds_entry() {
        let binders = vec![
            BindFactor {
                idx: 1,
                factor: s32("de9fa47304afaa64b5baddfccf4a8da6705edd162201ce55e1f9a478e6ec2a57"),
            },
            BindFactor {
                idx: 2,
                factor: s32("97aa7e9649ea9086359b7ba8fe815f54d98a5956ad63d2cf670d465d3b5d0f1f"),
            },
        ];
        let f = get_bind_factor(&binders, 1).unwrap();
        assert_eq!(
            hex::encode(f),
            "de9fa47304afaa64b5baddfccf4a8da6705edd162201ce55e1f9a478e6ec2a57"
        );
    }

    #[test]
    fn get_bind_factor_not_found_errors() {
        assert!(get_bind_factor(&[], 5).is_err());
    }

    // ── get_group_binders ─────────────────────────────────────────────────────

    #[test]
    fn get_group_binders_matches_fixture() {
        let group_pk = p33(TWEAKED_GROUP_PK);
        let msg = hex::decode(MESSAGE).unwrap();
        let prefix = get_group_prefix(&fixture_nonces(), &group_pk, &msg);
        let binders = get_group_binders(&fixture_nonces(), &prefix);
        assert_eq!(binders.len(), 2);
        let b1 = binders.iter().find(|b| b.idx == 1).unwrap();
        let b2 = binders.iter().find(|b| b.idx == 2).unwrap();
        assert_eq!(
            hex::encode(b1.factor),
            "de9fa47304afaa64b5baddfccf4a8da6705edd162201ce55e1f9a478e6ec2a57"
        );
        assert_eq!(
            hex::encode(b2.factor),
            "97aa7e9649ea9086359b7ba8fe815f54d98a5956ad63d2cf670d465d3b5d0f1f"
        );
    }

    // ── get_group_pubnonce ────────────────────────────────────────────────────

    #[test]
    fn get_group_pubnonce_matches_fixture() {
        let group_pk = p33(TWEAKED_GROUP_PK);
        let msg = hex::decode(MESSAGE).unwrap();
        let prefix = get_group_prefix(&fixture_nonces(), &group_pk, &msg);
        let binders = get_group_binders(&fixture_nonces(), &prefix);
        let pn = get_group_pubnonce(&fixture_nonces(), &binders).unwrap();
        assert_eq!(
            hex::encode(pn),
            "03e76328e49c27c12392a117d39ef9f5def368590d5e72438907fb63c1006fd589"
        );
    }

    #[test]
    fn get_group_pubnonce_empty_errors() {
        assert!(get_group_pubnonce(&[], &[]).is_err());
    }

    // ── create_commit_pkg ─────────────────────────────────────────────────────

    #[test]
    fn create_commit_pkg_matches_fixture() {
        let share = SecretShare {
            idx: 1,
            seckey: s32("0e74411caa9ef5ba058d0ccf4e54e1ee773e625fb7d6258097466cedab0de152"),
        };
        let hidden_seed = s32("0070ca75929ca1ec4cd70ac34f46079bdfdd87f9d0c0bf4275f3882f7b462d0f");
        let binder_seed = s32("0e0376a7180253cdb8b6020bff0eda529760da65e715663e2152e4be2fc7b443");
        let pkg = create_commit_pkg(&share, Some(&hidden_seed), Some(&binder_seed));

        assert_eq!(
            hex::encode(pkg.hidden_sn),
            "189aeb1bf3a453673cb144a459f0b644183ff02808cad807b672067da4f33357"
        );
        assert_eq!(
            hex::encode(pkg.binder_sn),
            "162f3098066a9407c7ce156cb0c49c58ab34b6e195b6435fa4be759e827b9b4c"
        );
        assert_eq!(
            hex::encode(pkg.hidden_pn),
            "024d837d707dfa4b56be26da22b9ff5cb0fd220d011351ba79334003f16871801c"
        );
        assert_eq!(
            hex::encode(pkg.binder_pn),
            "0263c0d31a58799213f5210685b8bc2ce4539819a90c09c216a983e8f8c67a12f5"
        );
    }

    #[test]
    fn create_commit_pkg_public_nonces_are_pubkeys() {
        let share = SecretShare {
            idx: 1,
            seckey: s32("0e74411caa9ef5ba058d0ccf4e54e1ee773e625fb7d6258097466cedab0de152"),
        };
        let seed = s32("0070ca75929ca1ec4cd70ac34f46079bdfdd87f9d0c0bf4275f3882f7b462d0f");
        let pkg = create_commit_pkg(&share, Some(&seed), Some(&seed));

        let expected_hidden =
            serialize_element(&scalar_base_multi(&scalar_from_bytes(&pkg.hidden_sn)));
        let expected_binder =
            serialize_element(&scalar_base_multi(&scalar_from_bytes(&pkg.binder_sn)));
        assert_eq!(
            pkg.hidden_pn, expected_hidden,
            "hidden_pn must be hidden_sn * G"
        );
        assert_eq!(
            pkg.binder_pn, expected_binder,
            "binder_pn must be binder_sn * G"
        );
    }

    // ── get_commit_pkg ────────────────────────────────────────────────────────

    #[test]
    fn get_commit_pkg_finds_share() {
        let share1 = SecretShare {
            idx: 1,
            seckey: s32("0e74411caa9ef5ba058d0ccf4e54e1ee773e625fb7d6258097466cedab0de152"),
        };
        let share2 = SecretShare {
            idx: 2,
            seckey: s32("1c77b7c3c2a14987be430edb4d63bc410e9f3cc59eeb8bbeb89951abdad59595"),
        };
        let seed = s32("0070ca75929ca1ec4cd70ac34f46079bdfdd87f9d0c0bf4275f3882f7b462d0f");
        let pkg1 = create_commit_pkg(&share1, Some(&seed), Some(&seed));
        let pkg2 = create_commit_pkg(&share2, Some(&seed), Some(&seed));
        let found = get_commit_pkg(&[pkg1, pkg2], &share2).unwrap();
        assert_eq!(found.idx, 2);
    }

    #[test]
    fn get_commit_pkg_not_found_errors() {
        let share = SecretShare {
            idx: 99,
            seckey: s32("0e74411caa9ef5ba058d0ccf4e54e1ee773e625fb7d6258097466cedab0de152"),
        };
        assert!(get_commit_pkg(&[], &share).is_err());
    }
}
