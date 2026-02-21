use crate::Error;
/// High-level threshold ECDH key derivation.
///
/// Allows a threshold quorum to collaboratively derive a shared secret
/// with any external public key, without any single member knowing the
/// full group private key.
use crate::ecdh::{create_ecdh_share, derive_ecdh_secret};
use crate::types::{PublicShare, SecretShare as LowSecretShare};

use super::types::{EcdhEntry, EcdhPackage, SharePackage};

/// Create an ECDH package for a single target public key.
///
/// `members` is the set of participant indices in the quorum (used for
/// Lagrange interpolation). The result contains this member's keyshare
/// contribution toward the shared secret with `ecdh_pk`.
pub fn create_ecdh_pkg(
    members: &[u32],
    ecdh_pk: &[u8; 33],
    share: &SharePackage,
) -> Result<EcdhPackage, Error> {
    let low_share = LowSecretShare {
        idx: share.idx,
        seckey: share.seckey,
    };
    let ecdh_share = create_ecdh_share(members, &low_share, ecdh_pk)?;
    Ok(EcdhPackage {
        idx: share.idx,
        members: members.to_vec(),
        entries: vec![EcdhEntry {
            ecdh_pk: *ecdh_pk,
            keyshare: ecdh_share.pubkey,
        }],
    })
}

/// Create an ECDH package for multiple target public keys in one call.
///
/// More efficient than calling [`create_ecdh_pkg`] in a loop when you
/// need shared secrets with several keys at once.
pub fn create_batched_ecdh_pkg(
    members: &[u32],
    ecdh_pks: &[[u8; 33]],
    share: &SharePackage,
) -> Result<EcdhPackage, Error> {
    let low_share = LowSecretShare {
        idx: share.idx,
        seckey: share.seckey,
    };
    let entries: Vec<EcdhEntry> = ecdh_pks
        .iter()
        .map(|pk| {
            let ecdh_share = create_ecdh_share(members, &low_share, pk)?;
            Ok(EcdhEntry {
                ecdh_pk: *pk,
                keyshare: ecdh_share.pubkey,
            })
        })
        .collect::<Result<_, Error>>()?;

    Ok(EcdhPackage {
        idx: share.idx,
        members: members.to_vec(),
        entries,
    })
}

/// Combine ECDH packages from all quorum members to derive the shared secret
/// for a single target public key.
///
/// `pkgs` must contain one package per quorum member, each with an entry
/// for `ecdh_pk`.
pub fn combine_ecdh_pkgs(pkgs: &[EcdhPackage], ecdh_pk: &[u8; 33]) -> Result<[u8; 33], Error> {
    let keyshares: Vec<PublicShare> = pkgs
        .iter()
        .map(|pkg| {
            let entry = pkg
                .entries
                .iter()
                .find(|e| &e.ecdh_pk == ecdh_pk)
                .ok_or_else(|| {
                    Error::Assertion(format!(
                        "ecdh_pk not found in package from member {}",
                        pkg.idx
                    ))
                })?;
            Ok(PublicShare {
                idx: pkg.idx,
                pubkey: entry.keyshare,
            })
        })
        .collect::<Result<_, Error>>()?;

    derive_ecdh_secret(&keyshares)
}

/// Combine ECDH packages for all target keys present in the batch.
///
/// Returns a `Vec` of `(ecdh_pk, shared_secret)` pairs, one per unique
/// target key found in the first package.
pub fn combine_batched_ecdh_pkgs(pkgs: &[EcdhPackage]) -> Result<Vec<([u8; 33], [u8; 33])>, Error> {
    if pkgs.is_empty() {
        return Ok(vec![]);
    }
    pkgs[0]
        .entries
        .iter()
        .map(|entry| {
            let secret = combine_ecdh_pkgs(pkgs, &entry.ecdh_pk)?;
            Ok((entry.ecdh_pk, secret))
        })
        .collect()
}
