#[cfg(test)]
mod tests {
    use crate::context::get_group_signing_ctx;
    use crate::sign::*;
    use crate::types::{PublicNonce, SecretNonce, SecretShare, ShareSignature};

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

    fn tweaks() -> Vec<[u8; 32]> {
        vec![
            s32("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            s32("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
        ]
    }

    fn build_ctx() -> crate::types::GroupSigningCtx {
        let group_pk = p33("021ae63bc9ddaffe52d44c3018e83115bfb22195bd8112fcad112310714e6fd5ec");
        let msg = hex::decode("68656c6c6f20776f726c6421").unwrap();
        get_group_signing_ctx(&group_pk, &fixture_nonces(), &msg, &tweaks()).unwrap()
    }

    fn fixture_psigs() -> Vec<ShareSignature> {
        vec![
            ShareSignature {
                idx: 1,
                pubkey: p33("0278f55809a11a1016d13ec4f54674810abe4a6fec8b586e14f90d0c1f80de33eb"),
                psig: s32("89ce878d8aa2f6c6565e963c6bbe99c45af811a2892c402b4c4e3f9ad972a48b"),
            },
            ShareSignature {
                idx: 2,
                pubkey: p33("02f00d2b4d3b761ed6317310ed791234dfcad643c00000690e9601adc412b1a22d"),
                psig: s32("67488a00fc37386e12eddfd8eee2dcf997fc01255e7ea66f605db448c86363b1"),
            },
        ]
    }

    // ── sign_msg ──────────────────────────────────────────────────────────────

    #[test]
    fn sign_msg_matches_fixture_share1() {
        let ctx = build_ctx();
        let share = SecretShare {
            idx: 1,
            seckey: s32("0e74411caa9ef5ba058d0ccf4e54e1ee773e625fb7d6258097466cedab0de152"),
        };
        let snonce = SecretNonce {
            idx: 1,
            hidden_sn: s32("189aeb1bf3a453673cb144a459f0b644183ff02808cad807b672067da4f33357"),
            binder_sn: s32("162f3098066a9407c7ce156cb0c49c58ab34b6e195b6435fa4be759e827b9b4c"),
        };
        let sig = sign_msg(&ctx, &share, &snonce).unwrap();
        assert_eq!(
            hex::encode(sig.pubkey),
            "0278f55809a11a1016d13ec4f54674810abe4a6fec8b586e14f90d0c1f80de33eb"
        );
        assert_eq!(
            hex::encode(sig.psig),
            "89ce878d8aa2f6c6565e963c6bbe99c45af811a2892c402b4c4e3f9ad972a48b"
        );
    }

    #[test]
    fn sign_msg_matches_fixture_share2() {
        let ctx = build_ctx();
        let share = SecretShare {
            idx: 2,
            seckey: s32("1c77b7c3c2a14987be430edb4d63bc410e9f3cc59eeb8bbeb89951abdad59595"),
        };
        let snonce = SecretNonce {
            idx: 2,
            hidden_sn: s32("1c48193192f4a7ba98b04f21246da1925fdacd387ac79bb9708062c705f37a17"),
            binder_sn: s32("f3ede9cd66b93ce18af27792521c929c10cf21a45d72892db7d8a5088bd2ea2e"),
        };
        let sig = sign_msg(&ctx, &share, &snonce).unwrap();
        assert_eq!(
            hex::encode(sig.pubkey),
            "02f00d2b4d3b761ed6317310ed791234dfcad643c00000690e9601adc412b1a22d"
        );
        assert_eq!(
            hex::encode(sig.psig),
            "67488a00fc37386e12eddfd8eee2dcf997fc01255e7ea66f605db448c86363b1"
        );
    }

    #[test]
    fn sign_msg_mismatched_index_errors() {
        let ctx = build_ctx();
        let share = SecretShare {
            idx: 1,
            seckey: s32("0e74411caa9ef5ba058d0ccf4e54e1ee773e625fb7d6258097466cedab0de152"),
        };
        let snonce = SecretNonce {
            idx: 2, // wrong
            hidden_sn: s32("189aeb1bf3a453673cb144a459f0b644183ff02808cad807b672067da4f33357"),
            binder_sn: s32("162f3098066a9407c7ce156cb0c49c58ab34b6e195b6435fa4be759e827b9b4c"),
        };
        assert!(sign_msg(&ctx, &share, &snonce).is_err());
    }

    // ── verify_partial_sig ────────────────────────────────────────────────────

    #[test]
    fn verify_partial_sig_accepts_valid_sig() {
        let ctx = build_ctx();
        let pnonce = &fixture_nonces()[0];
        let share_pk = p33("0278f55809a11a1016d13ec4f54674810abe4a6fec8b586e14f90d0c1f80de33eb");
        let psig = s32("89ce878d8aa2f6c6565e963c6bbe99c45af811a2892c402b4c4e3f9ad972a48b");
        assert!(verify_partial_sig(&ctx, pnonce, &share_pk, &psig).unwrap());
    }

    #[test]
    fn verify_partial_sig_rejects_tampered_sig() {
        let ctx = build_ctx();
        let pnonce = &fixture_nonces()[0];
        let share_pk = p33("0278f55809a11a1016d13ec4f54674810abe4a6fec8b586e14f90d0c1f80de33eb");
        let mut psig = s32("89ce878d8aa2f6c6565e963c6bbe99c45af811a2892c402b4c4e3f9ad972a48b");
        psig[0] ^= 0xff;
        assert!(!verify_partial_sig(&ctx, pnonce, &share_pk, &psig).unwrap());
    }

    // ── combine_partial_sigs ──────────────────────────────────────────────────

    #[test]
    fn combine_partial_sigs_matches_fixture() {
        let ctx = build_ctx();
        let sig = combine_partial_sigs(&ctx, &fixture_psigs()).unwrap();
        assert_eq!(
            hex::encode(sig),
            "e76328e49c27c12392a117d39ef9f5def368590d5e72438907fb63c1006fd5891d715fa750b5840610aaf531949f633c4555ac20caf290c3f22cc0771f074447"
        );
    }

    // ── verify_final_sig ──────────────────────────────────────────────────────

    #[test]
    fn verify_final_sig_accepts_valid_signature() {
        let ctx = build_ctx();
        let sig = combine_partial_sigs(&ctx, &fixture_psigs()).unwrap();
        let key_ctx = ctx.key_context();
        let msg = hex::decode("68656c6c6f20776f726c6421").unwrap();
        assert!(verify_final_sig(&key_ctx, &msg, &sig).unwrap());
    }

    #[test]
    fn verify_final_sig_rejects_tampered_signature() {
        let ctx = build_ctx();
        let mut sig = combine_partial_sigs(&ctx, &fixture_psigs()).unwrap();
        sig[63] ^= 0xff;
        let key_ctx = ctx.key_context();
        let msg = hex::decode("68656c6c6f20776f726c6421").unwrap();
        assert!(!verify_final_sig(&key_ctx, &msg, &sig).unwrap());
    }
}
