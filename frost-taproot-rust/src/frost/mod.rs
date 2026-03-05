/// High-level FROST threshold signing API.
///
/// This module provides use-case-focused utilities for:
/// - **Distributed key generation** (trusted dealer): [`dealer`]
/// - **Nonce management**: [`nonce`]
/// - **Collaborative signing**: [`signing`]
/// - **Shared key derivation** (threshold ECDH): [`ecdh`]
///
/// # Quick start
///
/// ```rust
/// use frost_taproot::frost::{dealer, nonce, signing, ecdh};
///
/// // 1. Generate a 2-of-3 group (trusted dealer).
/// let pkg = dealer::generate_dealer_package(2, 3, &[]).unwrap();
///
/// // 2. Each signer generates a nonce pair before each signing round.
/// let nonce_pair = nonce::generate_nonce_pair(&pkg.shares[0].seckey);
///
/// // 3. Collect nonces from all participating signers, then create a session.
/// // 4. Each signer produces a partial signature.
/// // 5. Combine partial signatures into a final BIP340 signature.
/// ```
pub mod dealer;
pub mod dkg;
pub mod ecdh;
pub mod nonce;
pub mod signing;
pub mod types;

#[cfg(test)]
mod tests;

pub use types::*;
