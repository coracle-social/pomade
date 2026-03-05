#![allow(clippy::type_complexity)]
#![allow(clippy::needless_range_loop)]

pub mod ecc;
pub mod frost;
pub mod types;
pub mod util;

pub mod commit;
pub mod context;
pub mod ecdh;
pub mod group;
pub mod helpers;
pub mod poly;
pub mod recover;
pub mod refresh;
pub mod shares;
pub mod sign;
pub mod vss;

#[cfg(test)]
mod ecdh_tests;
#[cfg(test)]
mod group_tests;
#[cfg(test)]
mod helpers_tests;
#[cfg(test)]
mod poly_tests;
#[cfg(test)]
mod recover_tests;
#[cfg(test)]
mod refresh_tests;
#[cfg(test)]
mod shares_tests;
#[cfg(test)]
mod vss_tests;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("assertion failed: {0}")]
    Assertion(String),

    #[error("invalid point encoding")]
    InvalidPoint,

    #[error("both points are null")]
    BothPointsNull,

    #[error("scalar inversion failed (zero scalar)")]
    ScalarInversion,

    #[error("record not found for index: {0}")]
    RecordNotFound(u32),
}
