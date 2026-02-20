// Mirrors ref/frost/src/lib/context.ts

use crate::commit::{get_group_binders, get_group_prefix, get_group_pubnonce, get_nonce_ids};
use crate::ecc::group::serialize_element;
use crate::ecc::state::get_point_state;
use crate::ecc::util::lift_x;
use crate::helpers::get_challenge;
use crate::types::{GroupCommitContext, GroupKeyContext, GroupSigningCtx, PublicNonce};
use crate::Error;

/// Build the group key context, applying optional tweaks.
/// Mirrors `get_group_key_context` in the TS implementation.
pub fn get_group_key_context(pubkey: &[u8], tweaks: &[[u8; 32]]) -> Result<GroupKeyContext, Error> {
    let int_pt = lift_x(pubkey)?;
    let int_pk_bytes = serialize_element(&int_pt);

    let group_pt = get_point_state(int_pt, tweaks)?;
    let group_pk = serialize_element(&group_pt.point);

    Ok(GroupKeyContext {
        group_pt,
        group_pk,
        int_pt: Some(int_pt),
        int_pk: Some(int_pk_bytes),
        tweak: None,
    })
}

/// Build the commit context from the key context, nonces, and message.
/// Mirrors `get_group_commit_context` in the TS implementation.
pub fn get_group_commit_context(
    key_ctx: &GroupKeyContext,
    pnonces: &[PublicNonce],
    message: &[u8],
) -> Result<GroupCommitContext, Error> {
    let bind_prefix = get_group_prefix(pnonces, &key_ctx.group_pk, message);
    let bind_factors = get_group_binders(pnonces, &bind_prefix);
    let group_pn = get_group_pubnonce(pnonces, &bind_factors)?;
    let indexes = get_nonce_ids(pnonces);
    let challenge = get_challenge(&group_pn, &key_ctx.group_pk, message)?;

    Ok(GroupCommitContext {
        bind_factors,
        bind_prefix,
        challenge,
        group_pn,
        indexes,
        message: message.to_vec(),
        pnonces: pnonces.to_vec(),
    })
}

/// Build the full signing context.
/// Mirrors `get_group_signing_ctx` in the TS implementation.
pub fn get_group_signing_ctx(
    group_pk: &[u8],
    pnonces: &[PublicNonce],
    message: &[u8],
    tweaks: &[[u8; 32]],
) -> Result<GroupSigningCtx, Error> {
    let key_ctx = get_group_key_context(group_pk, tweaks)?;
    let com_ctx = get_group_commit_context(&key_ctx, pnonces, message)?;

    Ok(GroupSigningCtx {
        group_pt: key_ctx.group_pt,
        group_pk: key_ctx.group_pk,
        int_pt: key_ctx.int_pt,
        int_pk: key_ctx.int_pk,
        tweak: key_ctx.tweak,
        bind_factors: com_ctx.bind_factors,
        bind_prefix: com_ctx.bind_prefix,
        challenge: com_ctx.challenge,
        group_pn: com_ctx.group_pn,
        indexes: com_ctx.indexes,
        message: com_ctx.message,
        pnonces: com_ctx.pnonces,
    })
}
