// Unit tests for the ecc module.

#[cfg(test)]
mod util_tests {
    use crate::ecc::util::*;
    use k256::{ProjectivePoint, Scalar, U256};

    fn s(hex: &str) -> [u8; 32] {
        let b = hex::decode(hex).unwrap();
        b.try_into().unwrap()
    }

    fn p(hex: &str) -> [u8; 33] {
        let b = hex::decode(hex).unwrap();
        b.try_into().unwrap()
    }

    // ── mod_n ────────────────────────────────────────────────────────────────

    #[test]
    fn mod_n_zero_is_zero() {
        assert_eq!(mod_n(U256::ZERO), Scalar::ZERO);
    }

    #[test]
    fn mod_n_one_is_one() {
        assert_eq!(mod_n(U256::ONE), Scalar::ONE);
    }

    #[test]
    fn mod_n_reduces_n_to_zero() {
        // N mod N = 0
        assert_eq!(mod_n(N), Scalar::ZERO);
    }

    #[test]
    fn mod_n_reduces_n_plus_one_to_one() {
        let n_plus_one = N.wrapping_add(&U256::ONE);
        assert_eq!(mod_n(n_plus_one), Scalar::ONE);
    }

    // ── scalar_from_bytes / scalar_to_bytes ──────────────────────────────────

    #[test]
    fn scalar_roundtrip() {
        let bytes = s("0e74411caa9ef5ba058d0ccf4e54e1ee773e625fb7d6258097466cedab0de152");
        let scalar = scalar_from_bytes(&bytes);
        assert_eq!(scalar_to_bytes(&scalar), bytes);
    }

    #[test]
    fn scalar_from_zero_bytes() {
        let bytes = [0u8; 32];
        assert_eq!(scalar_from_bytes(&bytes), Scalar::ZERO);
    }

    // ── pow_n ────────────────────────────────────────────────────────────────

    #[test]
    fn pow_n_exp_zero_is_one() {
        assert_eq!(pow_n(5, 0), Scalar::ONE);
        assert_eq!(pow_n(0, 0), Scalar::ONE);
    }

    #[test]
    fn pow_n_exp_one_is_base() {
        let three = scalar_from_bytes(&{
            let mut b = [0u8; 32];
            b[31] = 3;
            b
        });
        assert_eq!(pow_n(3, 1), three);
    }

    #[test]
    fn pow_n_three_to_four() {
        // 3^4 = 81 = 0x51
        let expected = scalar_from_bytes(&{
            let mut b = [0u8; 32];
            b[31] = 81;
            b
        });
        assert_eq!(pow_n(3, 4), expected);
    }

    #[test]
    fn pow_n_two_to_eight() {
        // 2^8 = 256 = 0x0100
        let expected = scalar_from_bytes(&{
            let mut b = [0u8; 32];
            b[30] = 1;
            b[31] = 0;
            b
        });
        assert_eq!(pow_n(2, 8), expected);
    }

    // ── lift_x ───────────────────────────────────────────────────────────────

    #[test]
    fn lift_x_32_bytes_gives_even_y_point() {
        // x-only: strip prefix from known compressed point
        let x_only =
            hex::decode("1ae63bc9ddaffe52d44c3018e83115bfb22195bd8112fcad112310714e6fd5ec")
                .unwrap();
        let pt = lift_x(&x_only).unwrap();
        assert!(has_even_y(&pt));
        let serialized = serialize_point(&pt);
        assert_eq!(serialized[0], 0x02);
    }

    #[test]
    fn lift_x_33_bytes_compressed() {
        let compressed = p("021ae63bc9ddaffe52d44c3018e83115bfb22195bd8112fcad112310714e6fd5ec");
        let pt = lift_x(&compressed).unwrap();
        assert!(has_even_y(&pt));
    }

    #[test]
    fn lift_x_odd_prefix_still_works() {
        // 0x03 prefix = odd Y; lift_x should still decode it
        let odd = p("034bc9f2ef5cc5eb741cc00d763e1077e8bc624df82d198781c71a0757617d8d44");
        let pt = lift_x(&odd).unwrap();
        // The point itself has odd Y
        assert!(!has_even_y(&pt));
    }

    #[test]
    fn lift_x_invalid_bytes_errors() {
        assert!(lift_x(&[0u8; 31]).is_err());
        assert!(lift_x(&[0u8; 34]).is_err());
        // All-zero 32 bytes is not a valid x-coordinate
        assert!(lift_x(&[0u8; 32]).is_err());
    }

    // ── serialize / deserialize ──────────────────────────────────────────────

    #[test]
    fn serialize_deserialize_roundtrip() {
        let pt = ProjectivePoint::GENERATOR;
        let bytes = serialize_point(&pt);
        let recovered = deserialize_point(&bytes).unwrap();
        assert_eq!(pt, recovered);
    }

    #[test]
    fn generator_serializes_correctly() {
        let pt = ProjectivePoint::GENERATOR;
        let bytes = serialize_point(&pt);
        assert_eq!(
            hex::encode(bytes),
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        );
    }

    // ── has_even_y / negate_point ────────────────────────────────────────────

    #[test]
    fn generator_has_even_y() {
        assert!(has_even_y(&ProjectivePoint::GENERATOR));
    }

    #[test]
    fn negate_flips_parity() {
        let pt = ProjectivePoint::GENERATOR;
        let neg = negate_point(&pt);
        assert!(!has_even_y(&neg));
        // Double negation is identity
        assert_eq!(negate_point(&neg), pt);
    }

    // ── scalar_invert ────────────────────────────────────────────────────────

    #[test]
    fn scalar_invert_of_one_is_one() {
        let inv = scalar_invert(&Scalar::ONE).unwrap();
        assert_eq!(inv, Scalar::ONE);
    }

    #[test]
    fn scalar_invert_of_zero_errors() {
        assert!(scalar_invert(&Scalar::ZERO).is_err());
    }

    #[test]
    fn scalar_invert_roundtrip() {
        let a = scalar_from_bytes(&s(
            "0e74411caa9ef5ba058d0ccf4e54e1ee773e625fb7d6258097466cedab0de152",
        ));
        let inv = scalar_invert(&a).unwrap();
        assert_eq!(a * inv, Scalar::ONE);
    }
}

#[cfg(test)]
mod group_tests {
    use crate::ecc::group::*;
    use k256::Scalar;

    fn p(hex: &str) -> [u8; 33] {
        let b = hex::decode(hex).unwrap();
        b.try_into().unwrap()
    }

    // ── scalar_base_multi ────────────────────────────────────────────────────

    #[test]
    fn scalar_base_multi_one_is_generator() {
        let g = scalar_base_multi(&Scalar::ONE);
        assert_eq!(
            hex::encode(serialize_element(&g)),
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        );
    }

    #[test]
    fn scalar_base_multi_known_value() {
        // 7*G
        let seven = crate::ecc::util::scalar_from_bytes(&{
            let mut b = [0u8; 32];
            b[31] = 7;
            b
        });
        let pt = scalar_base_multi(&seven);
        assert_eq!(
            hex::encode(serialize_element(&pt)),
            "025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc"
        );
    }

    // ── element_add ──────────────────────────────────────────────────────────

    #[test]
    fn element_add_2g_plus_3g_equals_5g() {
        let two = crate::ecc::util::scalar_from_bytes(&{
            let mut b = [0u8; 32];
            b[31] = 2;
            b
        });
        let three = crate::ecc::util::scalar_from_bytes(&{
            let mut b = [0u8; 32];
            b[31] = 3;
            b
        });
        let five = crate::ecc::util::scalar_from_bytes(&{
            let mut b = [0u8; 32];
            b[31] = 5;
            b
        });
        let a = scalar_base_multi(&two);
        let b = scalar_base_multi(&three);
        let c = element_add(Some(a), Some(b)).unwrap();
        let expected = scalar_base_multi(&five);
        assert_eq!(
            hex::encode(serialize_element(&c)),
            hex::encode(serialize_element(&expected))
        );
    }

    #[test]
    fn element_add_none_left_returns_right() {
        let g = scalar_base_multi(&Scalar::ONE);
        let result = element_add(None, Some(g)).unwrap();
        assert_eq!(serialize_element(&result), serialize_element(&g));
    }

    #[test]
    fn element_add_none_right_returns_left() {
        let g = scalar_base_multi(&Scalar::ONE);
        let result = element_add(Some(g), None).unwrap();
        assert_eq!(serialize_element(&result), serialize_element(&g));
    }

    #[test]
    fn element_add_both_none_errors() {
        assert!(element_add(None, None).is_err());
    }

    // ── scalar_multi ─────────────────────────────────────────────────────────

    #[test]
    fn scalar_multi_matches_base_multi() {
        let seven = crate::ecc::util::scalar_from_bytes(&{
            let mut b = [0u8; 32];
            b[31] = 7;
            b
        });
        let g = scalar_base_multi(&Scalar::ONE);
        let result = scalar_multi(&g, &seven);
        let expected = scalar_base_multi(&seven);
        assert_eq!(serialize_element(&result), serialize_element(&expected));
    }

    // ── serialize_scalar_u32 ─────────────────────────────────────────────────

    #[test]
    fn serialize_scalar_u32_zero() {
        assert_eq!(serialize_scalar_u32(0), [0u8; 32]);
    }

    #[test]
    fn serialize_scalar_u32_one() {
        let mut expected = [0u8; 32];
        expected[31] = 1;
        assert_eq!(serialize_scalar_u32(1), expected);
    }

    #[test]
    fn serialize_scalar_u32_large() {
        let mut expected = [0u8; 32];
        expected[28..].copy_from_slice(&0x01020304u32.to_be_bytes());
        assert_eq!(serialize_scalar_u32(0x01020304), expected);
    }
}

#[cfg(test)]
mod hash_tests {
    use crate::ecc::hash::*;

    // All expected values verified against the cmdruid/frost TypeScript implementation.

    #[test]
    fn h1_empty_input() {
        let result = h1(&[]);
        assert_eq!(
            hex::encode(result),
            "28d6cedb3fba18f85dbb373d8b01328464bf020f6ad651d877998f70f2980fd0"
        );
    }

    #[test]
    fn h2_empty_input() {
        let result = h2(&[]);
        assert_eq!(
            hex::encode(result),
            "ac6482b13a7f3ae0cbb38157c557f1857bf480c77c63e19e73e8070d98c86fc3"
        );
    }

    #[test]
    fn h3_empty_input() {
        let result = h3(&[]);
        assert_eq!(
            hex::encode(result),
            "2da9f94fe1dde8b15546272af0cad7c8ba7c4a58e8ec7087521055161c8fbc03"
        );
    }

    #[test]
    fn h3_known_input() {
        // generate_nonce(share[1].seckey, hidden_seed) from the fixture
        let input = hex::decode(
            "0070ca75929ca1ec4cd70ac34f46079bdfdd87f9d0c0bf4275f3882f7b462d0f\
             0e74411caa9ef5ba058d0ccf4e54e1ee773e625fb7d6258097466cedab0de152",
        )
        .unwrap();
        assert_eq!(
            hex::encode(h3(&input)),
            "189aeb1bf3a453673cb144a459f0b644183ff02808cad807b672067da4f33357"
        );
    }

    #[test]
    fn h4_empty_input() {
        let result = h4(&[]);
        assert_eq!(
            hex::encode(result),
            "578967b1c52aeeb9d8c64aa02fbe2cf7f171b58f2547dbeb349be5eff9ba1549"
        );
    }

    #[test]
    fn h4_known_input() {
        // "test" in hex = 74657374
        let input = hex::decode("74657374").unwrap();
        assert_eq!(
            hex::encode(h4(&input)),
            "ff9b5210ffbb3c07a73a7c8935be4a8c62cf015f6cf7ade6efac09a6513540fc"
        );
    }

    #[test]
    fn h5_known_input() {
        // Vector from hash.json
        let input = hex::decode(
            "000000000000000000000000000000000000000000000000000000000000000103c699af97d26bb4d3f05232ec5e1938c12f1e6ae97643c8f8f11c9820303f190402fa2aaccd51b948c9dc1a325d77226e98a5a3fe65fe9ba213761a60123040a45e000000000000000000000000000000000000000000000000000000000000000303077507ba327fc074d2793955ef3410ee3f03b82b4cdc2370f71d865beb926ef602ad53031ddfbbacfc5fbda3d3b0c2445c8e3e99cbc4ca2db2aa283fa68525b135",
        ).unwrap();
        assert_eq!(
            hex::encode(h5(&input)),
            "3f5a816aaebc2114a811a415d7a55db7c5cbc1cf27183e79dd9def941b5d4801"
        );
    }

    #[test]
    fn h1_h2_h3_differ_for_same_input() {
        // Different DSTs must produce different outputs
        let input = b"test";
        let r1 = h1(input);
        let r2 = h2(input);
        let r3 = h3(input);
        assert_ne!(r1, r2);
        assert_ne!(r2, r3);
        assert_ne!(r1, r3);
    }

    #[test]
    fn h4_h5_differ_for_same_input() {
        let input = b"test";
        assert_ne!(h4(input), h5(input));
    }
}

#[cfg(test)]
mod state_tests {
    use crate::ecc::{group::serialize_element, state::get_point_state, util::lift_x};

    fn h32(hex: &str) -> [u8; 32] {
        hex::decode(hex).unwrap().try_into().unwrap()
    }

    #[test]
    fn no_tweaks_returns_identity_state() {
        let pt = lift_x(
            &hex::decode("1ae63bc9ddaffe52d44c3018e83115bfb22195bd8112fcad112310714e6fd5ec")
                .unwrap(),
        )
        .unwrap();
        let state = get_point_state(pt, &[]).unwrap();
        // No tweaks: point unchanged, parity = +1 (even Y), state = +1, tweak = 0
        use k256::Scalar;
        assert_eq!(state.parity, Scalar::ONE);
        assert_eq!(state.state, Scalar::ONE);
        assert_eq!(state.tweak, Scalar::ZERO);
        assert_eq!(
            hex::encode(serialize_element(&state.point)),
            "021ae63bc9ddaffe52d44c3018e83115bfb22195bd8112fcad112310714e6fd5ec"
        );
    }

    #[test]
    fn tweaked_group_pk_matches_fixture() {
        // From the integration fixture: group_pk tweaked with aa...aa and bb...bb
        let group_pk =
            hex::decode("021ae63bc9ddaffe52d44c3018e83115bfb22195bd8112fcad112310714e6fd5ec")
                .unwrap();
        let pt = lift_x(&group_pk).unwrap();
        let tweaks = [
            h32("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            h32("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
        ];
        let state = get_point_state(pt, &tweaks).unwrap();
        assert_eq!(
            hex::encode(serialize_element(&state.point)),
            "025731d4d57552d12877e3db13061d7f6ca09198963e003d1d6e0960d6651e42d3"
        );
    }
}
