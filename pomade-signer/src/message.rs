#![allow(unused_imports, dead_code)]

pub use crate::schema::{
    ChallengeRequest, ChallengeResponse, EcdhRequest, EcdhResponse, LoginSelectRequest,
    LoginSelectResponse, LoginStartRequest, LoginStartResponse, RecoverySelectRequest,
    RecoverySelectResponse, RecoverySetupRequest, RecoverySetupResponse, RecoveryStartRequest,
    RecoveryStartResponse, RegisterRequest, RegisterResponse, SessionDeleteRequest,
    SessionDeleteResponse, SessionListRequest, SessionListResponse, SignRequest, SignResponse,
};

#[derive(Debug, Clone)]
pub struct Message<T> {
    pub url: String,
    pub res: Option<T>,
}
