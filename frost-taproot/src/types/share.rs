// Mirrors ref/frost/src/types/share.ts

/// A participant's secret share of the group key.
#[derive(Clone, Debug)]
pub struct SecretShare {
    pub idx: u32,
    pub seckey: [u8; 32],
}

/// A participant's public share (commitment).
#[derive(Clone, Debug)]
pub struct PublicShare {
    pub idx: u32,
    pub pubkey: [u8; 33],
}

/// A set of secret shares with VSS commitments, produced by one dealer/participant.
#[derive(Clone, Debug)]
pub struct SecretShareSet {
    pub shares: Vec<SecretShare>,
    pub vss_commits: Vec<[u8; 33]>,
}

/// A dealer-produced share set that also includes the group public key.
#[derive(Clone, Debug)]
pub struct DealerShareSet {
    pub shares: Vec<SecretShare>,
    pub vss_commits: Vec<[u8; 33]>,
    pub group_pk: [u8; 33],
}

/// A secret share set tagged with the originating participant index.
/// Mirrors `SecretSharePackage` in the TS implementation.
#[derive(Clone, Debug)]
pub struct SecretSharePackage {
    pub idx: u32,
    pub shares: Vec<SecretShare>,
    pub vss_commits: Vec<[u8; 33]>,
}
