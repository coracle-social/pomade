// Mirrors ref/frost/src/ecc/state.ts

use k256::{ProjectivePoint, Scalar};

use super::group::{element_add, scalar_base_multi};
use super::util::{has_even_y, mod_n, negate_point, scalar_from_bytes};
use crate::types::PointState;
use crate::Error;
use k256::U256;

/// Computes the accumulative parity state for a given point with optional key tweaks.
/// Mirrors `get_point_state` in the TS implementation.
pub fn get_point_state(element: ProjectivePoint, tweaks: &[[u8; 32]]) -> Result<PointState, Error> {
    let pos = Scalar::ONE;
    let neg = -pos; // N - 1 mod N

    let mut point = element;
    let mut parity;
    let mut state = pos;
    let mut tweak = Scalar::ZERO;

    for t_bytes in tweaks {
        let t = scalar_from_bytes(t_bytes);
        let tg = scalar_base_multi(&t);

        parity = if has_even_y(&point) { pos } else { neg };

        if parity == neg {
            point = negate_point(&point);
        }

        point = element_add(Some(point), Some(tg))?;

        state = state * parity;
        tweak = mod_n(U256::from_be_slice(&(t + parity * tweak).to_bytes()));
    }

    parity = if has_even_y(&point) { pos } else { neg };

    Ok(PointState {
        parity,
        point,
        state,
        tweak,
    })
}
