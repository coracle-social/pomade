// Mirrors ref/frost/src/types/ctx.ts

use k256::Scalar;

use super::{BindFactor, PointState, PublicNonce};

/// Key context: the group key and its tweaked state.
#[derive(Clone, Debug)]
pub struct GroupKeyContext {
    pub group_pt: PointState,
    pub group_pk: [u8; 33],
    pub int_pt: Option<k256::ProjectivePoint>,
    pub int_pk: Option<[u8; 33]>,
    pub tweak: Option<[u8; 32]>,
}

/// Commit context: everything derived from the nonces and message.
#[derive(Clone, Debug)]
pub struct GroupCommitContext {
    pub bind_factors: Vec<BindFactor>,
    pub bind_prefix: Vec<u8>,
    pub challenge: Scalar,
    pub group_pn: [u8; 33],
    pub indexes: Vec<u32>,
    pub message: Vec<u8>,
    pub pnonces: Vec<PublicNonce>,
}

/// Full signing context = key context + commit context.
#[derive(Clone, Debug)]
pub struct GroupSigningCtx {
    // Key context fields
    pub group_pt: PointState,
    pub group_pk: [u8; 33],
    pub int_pt: Option<k256::ProjectivePoint>,
    pub int_pk: Option<[u8; 33]>,
    pub tweak: Option<[u8; 32]>,
    // Commit context fields
    pub bind_factors: Vec<BindFactor>,
    pub bind_prefix: Vec<u8>,
    pub challenge: Scalar,
    pub group_pn: [u8; 33],
    pub indexes: Vec<u32>,
    pub message: Vec<u8>,
    pub pnonces: Vec<PublicNonce>,
}

impl GroupSigningCtx {
    pub fn key_context(&self) -> GroupKeyContext {
        GroupKeyContext {
            group_pt: self.group_pt.clone(),
            group_pk: self.group_pk,
            int_pt: self.int_pt,
            int_pk: self.int_pk,
            tweak: self.tweak,
        }
    }
}
