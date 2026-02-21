#[cfg(test)]
mod tests {
    use crate::helpers::*;

    fn s32(hex: &str) -> [u8; 32] {
        hex::decode(hex).unwrap().try_into().unwrap()
    }

    // ── generate_seckey ──────────────────────────────────────────────────────

    #[test]
    fn generate_seckey_deterministic_with_aux() {
        let aux = s32("0070ca75929ca1ec4cd70ac34f46079bdfdd87f9d0c0bf4275f3882f7b462d0f");
        let a = generate_seckey(Some(&aux));
        let b = generate_seckey(Some(&aux));
        assert_eq!(a, b);
    }

    #[test]
    fn generate_seckey_random_without_aux() {
        // Two calls without aux should (overwhelmingly) differ
        let a = generate_seckey(None);
        let b = generate_seckey(None);
        assert_ne!(a, b);
    }

    #[test]
    fn generate_seckey_is_h3_of_aux() {
        let aux = s32("0070ca75929ca1ec4cd70ac34f46079bdfdd87f9d0c0bf4275f3882f7b462d0f");
        let result = generate_seckey(Some(&aux));
        let expected = crate::ecc::hash::h3(&aux);
        assert_eq!(result, expected);
    }

    // ── generate_nonce ───────────────────────────────────────────────────────

    #[test]
    fn generate_nonce_deterministic_with_seed() {
        let secret = s32("0e74411caa9ef5ba058d0ccf4e54e1ee773e625fb7d6258097466cedab0de152");
        let seed = s32("0070ca75929ca1ec4cd70ac34f46079bdfdd87f9d0c0bf4275f3882f7b462d0f");
        let a = generate_nonce(&secret, Some(&seed));
        let b = generate_nonce(&secret, Some(&seed));
        assert_eq!(a, b);
    }

    #[test]
    fn generate_nonce_matches_fixture() {
        // hidden_sn for share[1]: generate_nonce(share1.seckey, hidden_seed)
        let secret = s32("0e74411caa9ef5ba058d0ccf4e54e1ee773e625fb7d6258097466cedab0de152");
        let seed = s32("0070ca75929ca1ec4cd70ac34f46079bdfdd87f9d0c0bf4275f3882f7b462d0f");
        let nonce = generate_nonce(&secret, Some(&seed));
        assert_eq!(
            hex::encode(nonce),
            "189aeb1bf3a453673cb144a459f0b644183ff02808cad807b672067da4f33357"
        );
    }

    #[test]
    fn generate_nonce_random_without_seed() {
        let secret = s32("0e74411caa9ef5ba058d0ccf4e54e1ee773e625fb7d6258097466cedab0de152");
        let a = generate_nonce(&secret, None);
        let b = generate_nonce(&secret, None);
        assert_ne!(a, b);
    }

    // ── get_pubkey ───────────────────────────────────────────────────────────

    #[test]
    fn get_pubkey_matches_fixture() {
        let seckey = s32("0e74411caa9ef5ba058d0ccf4e54e1ee773e625fb7d6258097466cedab0de152");
        let pubkey = get_pubkey(&seckey);
        assert_eq!(
            hex::encode(pubkey),
            "0278f55809a11a1016d13ec4f54674810abe4a6fec8b586e14f90d0c1f80de33eb"
        );
    }

    #[test]
    fn get_pubkey_is_compressed_33_bytes() {
        let seckey = s32("0e74411caa9ef5ba058d0ccf4e54e1ee773e625fb7d6258097466cedab0de152");
        let pubkey = get_pubkey(&seckey);
        assert!(pubkey[0] == 0x02 || pubkey[0] == 0x03);
    }

    // ── tweak_seckey ─────────────────────────────────────────────────────────

    #[test]
    fn tweak_seckey_by_one_is_identity() {
        let seckey = s32("0e74411caa9ef5ba058d0ccf4e54e1ee773e625fb7d6258097466cedab0de152");
        let one = s32("0000000000000000000000000000000000000000000000000000000000000001");
        assert_eq!(tweak_seckey(&seckey, &one), seckey);
    }

    #[test]
    fn tweak_seckey_doubles_with_two() {
        use crate::ecc::util::{scalar_from_bytes, scalar_to_bytes};
        let seckey = s32("0e74411caa9ef5ba058d0ccf4e54e1ee773e625fb7d6258097466cedab0de152");
        let two = s32("0000000000000000000000000000000000000000000000000000000000000002");
        let tweaked = tweak_seckey(&seckey, &two);
        let expected = scalar_to_bytes(&(scalar_from_bytes(&seckey) + scalar_from_bytes(&seckey)));
        assert_eq!(tweaked, expected);
    }

    // ── tweak_pubkey ─────────────────────────────────────────────────────────

    #[test]
    fn tweak_pubkey_by_one_is_identity() {
        let pubkey =
            hex::decode("021ae63bc9ddaffe52d44c3018e83115bfb22195bd8112fcad112310714e6fd5ec")
                .unwrap();
        let one = s32("0000000000000000000000000000000000000000000000000000000000000001");
        let tweaked = tweak_pubkey(&pubkey, &one).unwrap();
        assert_eq!(hex::encode(tweaked), hex::encode(&pubkey));
    }

    #[test]
    fn tweak_pubkey_invalid_input_errors() {
        let one = s32("0000000000000000000000000000000000000000000000000000000000000001");
        assert!(tweak_pubkey(&[0u8; 31], &one).is_err());
    }

    // ── get_challenge ────────────────────────────────────────────────────────

    #[test]
    fn get_challenge_matches_fixture() {
        use crate::ecc::util::scalar_to_bytes;
        // From the fixture signing context
        let group_pn =
            hex::decode("03e76328e49c27c12392a117d39ef9f5def368590d5e72438907fb63c1006fd589")
                .unwrap();
        let group_pk =
            hex::decode("025731d4d57552d12877e3db13061d7f6ca09198963e003d1d6e0960d6651e42d3")
                .unwrap();
        let message = hex::decode("68656c6c6f20776f726c6421").unwrap();
        let challenge = get_challenge(&group_pn, &group_pk, &message).unwrap();
        assert_eq!(
            hex::encode(scalar_to_bytes(&challenge)),
            "99e6637f68e223b0f6b4caa36b48cc277bf036ece4f14bab657200b43ecb0d55"
        );
    }

    #[test]
    fn get_challenge_invalid_pubkey_errors() {
        assert!(get_challenge(&[0u8; 31], &[0u8; 33], &[]).is_err());
        assert!(get_challenge(&[0u8; 33], &[0u8; 31], &[]).is_err());
    }

    // ── convert_pubkey_to_bip340 / convert_pubkey_to_ecdsa ──────────────────

    #[test]
    fn convert_to_bip340_strips_prefix() {
        let compressed =
            hex::decode("021ae63bc9ddaffe52d44c3018e83115bfb22195bd8112fcad112310714e6fd5ec")
                .unwrap();
        let bip340 = convert_pubkey_to_bip340(&compressed).unwrap();
        assert_eq!(bip340.len(), 32);
        assert_eq!(bip340, compressed[1..]);
    }

    #[test]
    fn convert_to_bip340_passthrough_32() {
        let x_only =
            hex::decode("1ae63bc9ddaffe52d44c3018e83115bfb22195bd8112fcad112310714e6fd5ec")
                .unwrap();
        let bip340 = convert_pubkey_to_bip340(&x_only).unwrap();
        assert_eq!(bip340, x_only);
    }

    #[test]
    fn convert_to_bip340_invalid_length_errors() {
        assert!(convert_pubkey_to_bip340(&[0u8; 31]).is_err());
        assert!(convert_pubkey_to_bip340(&[0u8; 34]).is_err());
    }

    #[test]
    fn convert_to_ecdsa_prepends_prefix() {
        let x_only =
            hex::decode("1ae63bc9ddaffe52d44c3018e83115bfb22195bd8112fcad112310714e6fd5ec")
                .unwrap();
        let ecdsa = convert_pubkey_to_ecdsa(&x_only).unwrap();
        assert_eq!(ecdsa.len(), 33);
        assert_eq!(ecdsa[0], 0x02);
        assert_eq!(&ecdsa[1..], x_only.as_slice());
    }

    #[test]
    fn convert_to_ecdsa_passthrough_33() {
        let compressed =
            hex::decode("021ae63bc9ddaffe52d44c3018e83115bfb22195bd8112fcad112310714e6fd5ec")
                .unwrap();
        let ecdsa = convert_pubkey_to_ecdsa(&compressed).unwrap();
        assert_eq!(ecdsa, compressed);
    }
}
