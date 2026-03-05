#[cfg(test)]
mod tests {
    use crate::context::*;
    use crate::ecc::group::serialize_element;
    use crate::ecc::util::lift_x;
    use crate::types::PublicNonce;

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
    const MESSAGE: &str = "68656c6c6f20776f726c6421";

    fn tweaks() -> Vec<[u8; 32]> {
        vec![
            s32("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            s32("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
        ]
    }

    // ── get_point_state ───────────────────────────────────────────────────────

    #[test]
    fn get_point_state_no_tweaks_identity() {
        use crate::ecc::state::get_point_state;
        use k256::Scalar;

        let pt = lift_x(&p33(GROUP_PK)).unwrap();
        let state = get_point_state(pt, &[]).unwrap();

        assert_eq!(state.parity, Scalar::ONE);
        assert_eq!(state.state, Scalar::ONE);
        assert_eq!(state.tweak, Scalar::ZERO);
        // Point must be unchanged (compare as serialized compressed bytes)
        let expected = serialize_element(&lift_x(&p33(GROUP_PK)).unwrap());
        assert_eq!(serialize_element(&state.point), expected);
    }

    #[test]
    fn get_point_state_tweaked_matches_fixture() {
        use crate::ecc::state::get_point_state;

        let pt = lift_x(&p33(GROUP_PK)).unwrap();
        let state = get_point_state(pt, &tweaks()).unwrap();
        let tweaked_pk = serialize_element(&state.point);
        assert_eq!(
            hex::encode(tweaked_pk),
            "025731d4d57552d12877e3db13061d7f6ca09198963e003d1d6e0960d6651e42d3"
        );
    }

    #[test]
    fn get_point_state_different_tweaks_produce_different_points() {
        use crate::ecc::state::get_point_state;

        let pt = lift_x(&p33(GROUP_PK)).unwrap();
        let t1 = vec![s32(
            "1111111111111111111111111111111111111111111111111111111111111111",
        )];
        let t2 = vec![s32(
            "2222222222222222222222222222222222222222222222222222222222222222",
        )];
        let s1 = get_point_state(pt, &t1).unwrap();
        let s2 = get_point_state(pt, &t2).unwrap();
        assert_ne!(serialize_element(&s1.point), serialize_element(&s2.point));
    }

    // ── get_group_key_context ─────────────────────────────────────────────────

    #[test]
    fn get_group_key_context_no_tweaks() {
        let key_ctx = get_group_key_context(&p33(GROUP_PK), &[]).unwrap();
        assert_eq!(hex::encode(key_ctx.group_pk), GROUP_PK);
        assert!(key_ctx.int_pk.is_some());
    }

    #[test]
    fn get_group_key_context_with_tweaks() {
        let key_ctx = get_group_key_context(&p33(GROUP_PK), &tweaks()).unwrap();
        assert_eq!(
            hex::encode(key_ctx.group_pk),
            "025731d4d57552d12877e3db13061d7f6ca09198963e003d1d6e0960d6651e42d3"
        );
        // int_pk must be the original (untweaked) key
        assert_ne!(key_ctx.group_pk, key_ctx.int_pk.unwrap());
    }

    #[test]
    fn get_group_key_context_invalid_pubkey_errors() {
        assert!(get_group_key_context(&[0u8; 31], &[]).is_err());
    }

    // ── get_group_signing_ctx ─────────────────────────────────────────────────

    #[test]
    fn get_group_signing_ctx_matches_fixture() {
        let group_pk = p33(GROUP_PK);
        let msg = hex::decode(MESSAGE).unwrap();
        let ctx = get_group_signing_ctx(&group_pk, &fixture_nonces(), &msg, &tweaks()).unwrap();

        assert_eq!(
            hex::encode(ctx.group_pk),
            "025731d4d57552d12877e3db13061d7f6ca09198963e003d1d6e0960d6651e42d3"
        );
        assert_eq!(
            hex::encode(ctx.group_pn),
            "03e76328e49c27c12392a117d39ef9f5def368590d5e72438907fb63c1006fd589"
        );
        use crate::ecc::util::scalar_to_bytes;
        assert_eq!(
            hex::encode(scalar_to_bytes(&ctx.challenge)),
            "99e6637f68e223b0f6b4caa36b48cc277bf036ece4f14bab657200b43ecb0d55"
        );
        assert_eq!(ctx.bind_factors.len(), 2);
        assert_eq!(ctx.indexes, vec![1u32, 2u32]);
    }

    #[test]
    fn get_group_signing_ctx_preserves_message() {
        let group_pk = p33(GROUP_PK);
        let msg = hex::decode(MESSAGE).unwrap();
        let ctx = get_group_signing_ctx(&group_pk, &fixture_nonces(), &msg, &[]).unwrap();
        assert_eq!(ctx.message, msg);
    }

    #[test]
    fn get_group_signing_ctx_key_context_extract() {
        let group_pk = p33(GROUP_PK);
        let msg = hex::decode(MESSAGE).unwrap();
        let ctx = get_group_signing_ctx(&group_pk, &fixture_nonces(), &msg, &tweaks()).unwrap();
        let key_ctx = ctx.key_context();
        assert_eq!(key_ctx.group_pk, ctx.group_pk);
    }
}
