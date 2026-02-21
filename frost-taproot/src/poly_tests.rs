#[cfg(test)]
mod tests {
    use crate::ecc::util::scalar_from_bytes;
    use crate::poly::*;
    use k256::Scalar;

    fn sc(n: u8) -> Scalar {
        scalar_from_bytes(&{
            let mut b = [0u8; 32];
            b[31] = n;
            b
        })
    }

    fn sc32(hex: &str) -> Scalar {
        scalar_from_bytes(&hex::decode(hex).unwrap().try_into().unwrap())
    }

    // ── evaluate_x ───────────────────────────────────────────────────────────

    #[test]
    fn evaluate_x_constant_polynomial() {
        // f(x) = 7  →  f(3) = 7
        let coeffs = [sc(7)];
        assert_eq!(evaluate_x(&coeffs, sc(3)).unwrap(), sc(7));
    }

    #[test]
    fn evaluate_x_linear() {
        // f(x) = 3 + 2x  →  f(1) = 5, f(2) = 7
        let coeffs = [sc(3), sc(2)];
        assert_eq!(evaluate_x(&coeffs, sc(1)).unwrap(), sc(5));
        assert_eq!(evaluate_x(&coeffs, sc(2)).unwrap(), sc(7));
    }

    #[test]
    fn evaluate_x_quadratic() {
        // f(x) = 3 + 2x + x^2  →  f(1) = 6, f(2) = 11
        let coeffs = [sc(3), sc(2), sc(1)];
        assert_eq!(evaluate_x(&coeffs, sc(1)).unwrap(), sc(6));
        assert_eq!(evaluate_x(&coeffs, sc(2)).unwrap(), sc(11));
    }

    #[test]
    fn evaluate_x_at_zero_errors() {
        let coeffs = [sc(1), sc(2)];
        assert!(evaluate_x(&coeffs, Scalar::ZERO).is_err());
    }

    #[test]
    fn evaluate_x_matches_fixture_shares() {
        // From the fixture: coeffs = [s0, s1], share[1].seckey and share[2].seckey
        let s0 = sc32("0070ca75929ca1ec4cd70ac34f46079bdfdd87f9d0c0bf4275f3882f7b462d0f");
        let s1 = sc32("0e0376a7180253cdb8b6020bff0eda529760da65e715663e2152e4be2fc7b443");
        let coeffs = [s0, s1];

        let share1 = evaluate_x(&coeffs, index_to_scalar(1)).unwrap();
        let share2 = evaluate_x(&coeffs, index_to_scalar(2)).unwrap();

        assert_eq!(
            hex::encode(share1.to_bytes()),
            "0e74411caa9ef5ba058d0ccf4e54e1ee773e625fb7d6258097466cedab0de152"
        );
        assert_eq!(
            hex::encode(share2.to_bytes()),
            "1c77b7c3c2a14987be430edb4d63bc410e9f3cc59eeb8bbeb89951abdad59595"
        );
    }

    // ── interpolate_root ─────────────────────────────────────────────────────

    #[test]
    fn interpolate_root_recovers_secret() {
        // secret=7, f(x) = 7 + 3x  →  f(1)=10, f(2)=13
        let points = [(sc(1), sc(10)), (sc(2), sc(13))];
        let secret = interpolate_root(&points).unwrap();
        assert_eq!(secret, sc(7));
    }

    #[test]
    fn interpolate_root_single_point() {
        // f(x) = 5 (constant)  →  f(1) = 5
        let points = [(sc(1), sc(5))];
        let secret = interpolate_root(&points).unwrap();
        assert_eq!(secret, sc(5));
    }

    #[test]
    fn interpolate_root_recovers_fixture_secret() {
        // From the fixture: shares[0] and shares[1] should recover s0
        let s0 = sc32("0070ca75929ca1ec4cd70ac34f46079bdfdd87f9d0c0bf4275f3882f7b462d0f");
        let share1 = sc32("0e74411caa9ef5ba058d0ccf4e54e1ee773e625fb7d6258097466cedab0de152");
        let share2 = sc32("1c77b7c3c2a14987be430edb4d63bc410e9f3cc59eeb8bbeb89951abdad59595");
        let points = [(index_to_scalar(1), share1), (index_to_scalar(2), share2)];
        assert_eq!(interpolate_root(&points).unwrap(), s0);
    }

    // ── interpolate_x ────────────────────────────────────────────────────────

    #[test]
    fn interpolate_x_not_in_set_errors() {
        let l = [sc(1), sc(2)];
        assert!(interpolate_x(&l, sc(3)).is_err());
    }

    #[test]
    fn interpolate_x_duplicate_errors() {
        let l = [sc(1), sc(1)];
        assert!(interpolate_x(&l, sc(1)).is_err());
    }

    #[test]
    fn interpolate_x_single_element() {
        // L = {1}, x = 1: numerator = 1 (empty product), denominator = 1 → result = 1
        let l = [sc(1)];
        assert_eq!(interpolate_x(&l, sc(1)).unwrap(), Scalar::ONE);
    }

    // ── calc_lagrange_coeff ──────────────────────────────────────────────────

    #[test]
    fn calc_lagrange_coeff_duplicate_errors() {
        let l = [sc(1), sc(1)];
        assert!(calc_lagrange_coeff(&l, sc(1), Scalar::ZERO).is_err());
    }

    #[test]
    fn calc_lagrange_coeff_two_party_at_zero() {
        // L = {1, 2}, P = 1, x = 0
        // numerator   = (0 - 2) = -2
        // denominator = (1 - 2) = -1
        // result = (-2)/(-1) = 2
        let l = [sc(1), sc(2)];
        let coeff = calc_lagrange_coeff(&l, sc(1), Scalar::ZERO).unwrap();
        assert_eq!(coeff, sc(2));
    }

    // ── index_to_scalar ──────────────────────────────────────────────────────

    #[test]
    fn index_to_scalar_one() {
        assert_eq!(index_to_scalar(1), Scalar::ONE);
    }

    #[test]
    fn index_to_scalar_zero() {
        assert_eq!(index_to_scalar(0), Scalar::ZERO);
    }

    #[test]
    fn index_to_scalar_large() {
        let expected = scalar_from_bytes(&{
            let mut b = [0u8; 32];
            b[28..].copy_from_slice(&255u32.to_be_bytes());
            b
        });
        assert_eq!(index_to_scalar(255), expected);
    }
}
