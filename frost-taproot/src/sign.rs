// Mirrors ref/frost/src/lib/sign.ts

use k256::{Scalar, elliptic_curve::point::AffineCoordinates};

use crate::Error;
use crate::commit::{get_bind_factor, get_group_binders, get_group_prefix, get_group_pubnonce};
use crate::ecc::group::{element_add, scalar_base_multi, scalar_multi};
use crate::ecc::util::{has_even_y, lift_x, scalar_from_bytes, scalar_to_bytes};
use crate::helpers::get_pubkey;
use crate::poly::{index_to_scalar, interpolate_x};
use crate::types::{
    GroupKeyContext, GroupSigningCtx, PublicNonce, SecretNonce, SecretShare, ShareSignature,
};

/// Produce a partial signature for a signing session.
/// Mirrors `sign_msg` in the TS implementation.
pub fn sign_msg(
    ctx: &GroupSigningCtx,
    share: &SecretShare,
    snonce: &SecretNonce,
) -> Result<ShareSignature, Error> {
    if snonce.idx != share.idx {
        return Err(Error::Assertion(format!(
            "commit index does not match share index: {} !== {}",
            snonce.idx, share.idx
        )));
    }

    let bind_factor_bytes = get_bind_factor(&ctx.bind_factors, share.idx)?;
    let bind_factor = scalar_from_bytes(&bind_factor_bytes);

    let indexes: Vec<Scalar> = ctx.indexes.iter().map(|&i| index_to_scalar(i)).collect();
    let coefficient = interpolate_x(&indexes, index_to_scalar(share.idx))?;

    let mut snonce_h = scalar_from_bytes(&snonce.hidden_sn);
    let mut snonce_b = scalar_from_bytes(&snonce.binder_sn);
    let seckey = scalar_from_bytes(&share.seckey);

    let r_elem = lift_x(&ctx.group_pn)?;
    if !has_even_y(&r_elem) {
        snonce_h = -snonce_h;
        snonce_b = -snonce_b;
    }

    // sk = parity * state * seckey  (mod N)
    let sk = ctx.group_pt.parity * ctx.group_pt.state * seckey;
    // nk = hidden_sn + binder_sn * bind_factor
    let nk = snonce_h + snonce_b * bind_factor;
    // ps = challenge * coefficient * sk + nk
    let ps = ctx.challenge * coefficient * sk + nk;

    Ok(ShareSignature {
        idx: share.idx,
        psig: scalar_to_bytes(&ps),
        pubkey: get_pubkey(&share.seckey),
    })
}

/// Aggregate partial signatures into a final BIP340 Schnorr signature (64 bytes).
/// Mirrors `combine_partial_sigs` in the TS implementation.
pub fn combine_partial_sigs(
    ctx: &GroupSigningCtx,
    psigs: &[ShareSignature],
) -> Result<[u8; 64], Error> {
    let commit_prefix = get_group_prefix(&ctx.pnonces, &ctx.group_pk, &ctx.message);
    let group_binders = get_group_binders(&ctx.pnonces, &commit_prefix);
    let group_pnonce = get_group_pubnonce(&ctx.pnonces, &group_binders)?;

    // Sum all partial signatures.
    let ps = psigs
        .iter()
        .map(|s| scalar_from_bytes(&s.psig))
        .fold(Scalar::ZERO, |acc, s| acc + s);

    // twk = challenge * parity * tweak
    let twk = ctx.challenge * ctx.group_pt.parity * ctx.group_pt.tweak;
    let s = ps + twk;

    // Signature = R_x (32 bytes) || s (32 bytes).
    // group_pnonce is a 33-byte compressed point; x-only is bytes [1..33].
    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&group_pnonce[1..]);
    sig[32..].copy_from_slice(&scalar_to_bytes(&s));
    Ok(sig)
}

/// Verify a partial signature from one participant.
/// Mirrors `verify_partial_sig` in the TS implementation.
pub fn verify_partial_sig(
    ctx: &GroupSigningCtx,
    pnonce: &PublicNonce,
    share_pk: &[u8; 33],
    share_psig: &[u8; 32],
) -> Result<bool, Error> {
    let binder = scalar_from_bytes(&get_bind_factor(&ctx.bind_factors, pnonce.idx)?);

    let mut hidden_elem = lift_x(&pnonce.hidden_pn)?;
    let mut binder_elem = lift_x(&pnonce.binder_pn)?;
    let public_elem = lift_x(share_pk)?;

    let r_elem = lift_x(&ctx.group_pn)?;
    if !has_even_y(&r_elem) {
        hidden_elem = -hidden_elem;
        binder_elem = -binder_elem;
    }

    let commit_elem = scalar_multi(&binder_elem, &binder);
    let nonce_elem = element_add(Some(hidden_elem), Some(commit_elem))?;

    let indexes: Vec<Scalar> = ctx.indexes.iter().map(|&i| index_to_scalar(i)).collect();
    let lambda_i = interpolate_x(&indexes, index_to_scalar(pnonce.idx))?;

    let state = ctx.group_pt.parity * ctx.group_pt.state;
    let chal = ctx.challenge * lambda_i * state;

    let sig = scalar_from_bytes(share_psig);
    let sg = scalar_base_multi(&sig);
    let pki = scalar_multi(&public_elem, &chal);
    let r = element_add(Some(nonce_elem), Some(pki))?;

    // Compare x-coordinates.
    Ok(sg.to_affine().x() == r.to_affine().x())
}

/// Verify a final aggregated BIP340 Schnorr signature.
/// Mirrors `verify_final_sig` in the TS implementation.
///
/// Uses `verify_raw` because noble's `schnorr.verify` passes the message directly
/// into the BIP340 challenge hash without pre-hashing it with SHA-256.
pub fn verify_final_sig(
    ctx: &GroupKeyContext,
    message: &[u8],
    signature: &[u8; 64],
) -> Result<bool, Error> {
    use k256::schnorr::{Signature, VerifyingKey};

    // group_pk is 33-byte compressed; BIP340 uses x-only (32 bytes).
    let pk_bytes: [u8; 32] = ctx.group_pk[1..].try_into().unwrap();
    let vk = VerifyingKey::from_bytes(&pk_bytes).map_err(|_| Error::InvalidPoint)?;
    let sig = Signature::try_from(signature.as_slice()).map_err(|_| Error::InvalidPoint)?;

    Ok(vk.verify_raw(message, &sig).is_ok())
}
