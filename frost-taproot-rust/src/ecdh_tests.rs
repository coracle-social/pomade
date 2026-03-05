#[cfg(test)]
mod tests {
    use crate::ecc::group::{scalar_multi, serialize_element};
    use crate::ecc::util::{lift_x, scalar_from_bytes};
    use crate::ecdh::*;
    use crate::group::create_dealer_set;
    use crate::helpers::{generate_seckey, get_pubkey};

    fn s32(hex: &str) -> [u8; 32] {
        hex::decode(hex).unwrap().try_into().unwrap()
    }

    fn p33(hex: &str) -> [u8; 33] {
        hex::decode(hex).unwrap().try_into().unwrap()
    }

    const S0: &str = "0070ca75929ca1ec4cd70ac34f46079bdfdd87f9d0c0bf4275f3882f7b462d0f";
    const S1: &str = "0e0376a7180253cdb8b6020bff0eda529760da65e715663e2152e4be2fc7b443";

    // ── create_ecdh_share ────────────────────────────────────────────────────

    #[test]
    fn create_ecdh_share_matches_fixture() {
        let secrets = [s32(S0), s32(S1)];
        let group = create_dealer_set(2, 3, &secrets).unwrap();

        // demo_seckey = generate_seckey(Some(aa...aa))
        let demo_aux = s32("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let demo_seckey = generate_seckey(Some(&demo_aux));
        let demo_pubkey = get_pubkey(&demo_seckey);

        let members = [1u32, 3u32];
        let ecdh1 = create_ecdh_share(&members, &group.shares[0], &demo_pubkey).unwrap();
        let ecdh3 = create_ecdh_share(&members, &group.shares[2], &demo_pubkey).unwrap();

        assert_eq!(ecdh1.idx, 1);
        assert_eq!(ecdh3.idx, 3);
        assert_eq!(
            hex::encode(ecdh1.pubkey),
            "0386c5b0f4bace78ef17d02b09e339b5a39f659dbbf1f3f531b9825df6836cfea9"
        );
        assert_eq!(
            hex::encode(ecdh3.pubkey),
            "023edaf055945d35006e1c52dd7a388e0c10b36eb55aa9d117853af87903cb54c0"
        );
    }

    // ── derive_ecdh_secret ───────────────────────────────────────────────────

    #[test]
    fn derive_ecdh_secret_matches_master_secret() {
        // The FROST ECDH shared secret must equal secret_key * demo_pubkey
        // = demo_seckey * group_pubkey (commutativity of scalar mult).
        let secrets = [s32(S0), s32(S1)];
        let group = create_dealer_set(2, 3, &secrets).unwrap();

        let demo_aux = s32("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let demo_seckey = generate_seckey(Some(&demo_aux));
        let demo_pubkey = get_pubkey(&demo_seckey);

        let members = [1u32, 3u32];
        let ecdh1 = create_ecdh_share(&members, &group.shares[0], &demo_pubkey).unwrap();
        let ecdh3 = create_ecdh_share(&members, &group.shares[2], &demo_pubkey).unwrap();

        let frost_secret = derive_ecdh_secret(&[ecdh1, ecdh3]).unwrap();

        // master_shared_secret = demo_seckey * group_pk (scalar mult of the group pubkey)
        let group_pk = group.group_pk;
        let group_pt = lift_x(&group_pk).unwrap();
        let master_secret =
            serialize_element(&scalar_multi(&group_pt, &scalar_from_bytes(&demo_seckey)));

        assert_eq!(
            hex::encode(frost_secret),
            hex::encode(master_secret),
            "FROST ECDH secret must match master shared secret"
        );
    }

    #[test]
    fn derive_ecdh_secret_matches_fixture() {
        let frost_secret = derive_ecdh_secret(&[
            crate::types::PublicShare {
                idx: 1,
                pubkey: p33("0386c5b0f4bace78ef17d02b09e339b5a39f659dbbf1f3f531b9825df6836cfea9"),
            },
            crate::types::PublicShare {
                idx: 3,
                pubkey: p33("023edaf055945d35006e1c52dd7a388e0c10b36eb55aa9d117853af87903cb54c0"),
            },
        ])
        .unwrap();
        assert_eq!(
            hex::encode(frost_secret),
            "020b6417cef5530ed4b82681945d4565ea7027f423a97b60247d07386ca3619585"
        );
    }

    #[test]
    fn derive_ecdh_secret_empty_errors() {
        assert!(derive_ecdh_secret(&[]).is_err());
    }

    #[test]
    fn create_ecdh_share_invalid_pubkey_errors() {
        let share = crate::types::SecretShare {
            idx: 1,
            seckey: s32("0e74411caa9ef5ba058d0ccf4e54e1ee773e625fb7d6258097466cedab0de152"),
        };
        // All-zero pubkey is invalid
        assert!(create_ecdh_share(&[1u32, 2u32], &share, &[0u8; 33]).is_err());
    }
}
