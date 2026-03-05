// Mirrors ref/frost/src/lib/ecdh.ts

use k256::Scalar;

use crate::Error;
use crate::ecc::group::{element_add, scalar_multi, serialize_element};
use crate::ecc::util::{lift_x, scalar_from_bytes};
use crate::poly::{calc_lagrange_coeff, index_to_scalar};
use crate::types::{PublicShare, SecretShare};

/// Compute an ECDH share: a participant's contribution to a shared secret.
/// Mirrors `create_ecdh_share` in the TS implementation.
pub fn create_ecdh_share(
    members: &[u32],
    share: &SecretShare,
    pubkey: &[u8],
) -> Result<PublicShare, Error> {
    let mbrs: Vec<Scalar> = members
        .iter()
        .filter(|&&idx| idx != share.idx)
        .map(|&idx| index_to_scalar(idx))
        .collect();

    let idx = index_to_scalar(share.idx);
    let secret = scalar_from_bytes(&share.seckey);
    let point = lift_x(pubkey)?;

    let l_coeff = calc_lagrange_coeff(&mbrs, idx, Scalar::ZERO)?;
    let p_coeff = l_coeff * secret;
    let ecdh_pt = scalar_multi(&point, &p_coeff);

    Ok(PublicShare {
        idx: share.idx,
        pubkey: serialize_element(&ecdh_pt),
    })
}

/// Derive the shared ECDH secret by summing all participant ECDH shares.
/// Mirrors `derive_ecdh_secret` in the TS implementation.
pub fn derive_ecdh_secret(shares: &[PublicShare]) -> Result<[u8; 33], Error> {
    let mut point = None;
    for share in shares {
        let pt = lift_x(&share.pubkey)?;
        point = Some(element_add(point, Some(pt))?);
    }
    let pt = point.ok_or(Error::BothPointsNull)?;
    Ok(serialize_element(&pt))
}
