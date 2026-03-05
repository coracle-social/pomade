/// High-level types for the FROST threshold signing protocol.
///
/// These mirror the bifrost TypeScript types, using raw byte arrays
/// rather than hex strings for efficiency.
/// A member's secret share of the group key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharePackage {
    /// Participant index (1-based).
    pub idx: u32,
    /// 32-byte secret scalar.
    pub seckey: [u8; 32],
}

/// A member's public identity within a group.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberPackage {
    /// Participant index (1-based).
    pub idx: u32,
    /// 33-byte compressed public key of this member's aggregate secret share (`seckey * G`).
    /// Used for partial signature verification.
    pub pubkey: [u8; 33],
    /// DKG only: the first VSS commitment from this participant's Round 1 broadcast
    /// (`a_i0 * G`), i.e. their individual identity public key.
    /// `None` in the trusted dealer model.
    pub identity_pk: Option<[u8; 33]>,
}

/// The group's public state: group key + member roster + threshold.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupPackage {
    /// 33-byte compressed group public key.
    pub group_pk: [u8; 33],
    /// Minimum number of signers required.
    pub threshold: usize,
    /// All member public packages.
    pub members: Vec<MemberPackage>,
}

/// Output of the trusted dealer: group info + all secret shares.
#[derive(Clone, Debug)]
pub struct DealerPackage {
    pub group: GroupPackage,
    pub shares: Vec<SharePackage>,
}

/// A public nonce commitment (no secret material).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicNonce {
    /// 33-byte compressed binder nonce point.
    pub binder_pn: [u8; 33],
    /// 33-byte compressed hidden nonce point.
    pub hidden_pn: [u8; 33],
}

/// A public nonce with a derivation code for secret re-derivation.
/// Store the code; re-derive secrets on demand during signing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DerivedNonce {
    /// 33-byte compressed binder nonce point.
    pub binder_pn: [u8; 33],
    /// 33-byte compressed hidden nonce point.
    pub hidden_pn: [u8; 33],
    /// 32-byte random derivation code.
    pub code: [u8; 32],
}

/// A derived nonce tagged with the owning member's index.
/// Used in signing wire format.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberNonce {
    pub idx: u32,
    pub binder_pn: [u8; 33],
    pub hidden_pn: [u8; 33],
    pub code: [u8; 32],
}

/// Secret nonce pair re-derived from a code during signing.
#[derive(Clone, Debug)]
pub struct SecretNoncePair {
    /// The derivation code this was derived from.
    pub code: [u8; 32],
    /// 32-byte secret binder nonce scalar.
    pub binder_sn: [u8; 32],
    /// 32-byte secret hidden nonce scalar.
    pub hidden_sn: [u8; 32],
}

/// A signing session: the set of messages and participating members.
#[derive(Clone, Debug)]
pub struct SignSession {
    /// Unique session identifier (SHA-256 of session contents).
    pub sid: [u8; 32],
    /// 33-byte compressed group public key (after any tweaks are applied).
    pub group_pk: [u8; 33],
    /// Sorted list of participating member indices.
    pub members: Vec<u32>,
    /// Messages to sign. Each entry is `(message_bytes, tweaks)`.
    pub messages: Vec<(Vec<u8>, Vec<[u8; 32]>)>,
    /// Public nonces from all participating members.
    pub nonces: Vec<MemberNonce>,
}

/// A partial signature produced by one member for one message.
#[derive(Clone, Debug)]
pub struct PartialSig {
    /// The message this partial sig covers.
    pub message: Vec<u8>,
    /// 32-byte partial signature scalar.
    pub psig: [u8; 32],
}

/// A partial signature package from one member covering all session messages.
#[derive(Clone, Debug)]
pub struct PartialSigPackage {
    /// The member's index.
    pub idx: u32,
    /// The member's public key.
    pub pubkey: [u8; 33],
    /// Session ID this package belongs to.
    pub sid: [u8; 32],
    /// One partial sig per message in the session.
    pub psigs: Vec<PartialSig>,
}

/// A completed signature for one message.
#[derive(Clone, Debug)]
pub struct Signature {
    /// The message that was signed.
    pub message: Vec<u8>,
    /// 33-byte compressed group public key.
    pub pubkey: [u8; 33],
    /// 64-byte BIP340 Schnorr signature.
    pub sig: [u8; 64],
}

/// One participant's Round 1 broadcast: their VSS commitments.
/// Keep the corresponding secret coefficients private; broadcast this.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DkgCommitPackage {
    /// This participant's index (1-based).
    pub idx: u32,
    /// VSS commitments: one compressed point per polynomial coefficient.
    pub vss_commits: Vec<[u8; 33]>,
}

/// One participant's Round 2 private message to a specific recipient.
/// Send this only to the participant identified by `recipient_idx`.
#[derive(Clone, Debug)]
pub struct DkgSharePackage {
    /// Index of the participant who generated this share.
    pub sender_idx: u32,
    /// Index of the intended recipient.
    pub recipient_idx: u32,
    /// 32-byte secret share scalar (private — send only to recipient).
    pub seckey: [u8; 32],
}

/// A participant's complete local state after DKG finalization.
#[derive(Clone, Debug)]
pub struct DkgOutput {
    /// This participant's aggregate secret share of the group key.
    pub share: SharePackage,
    /// The group's public state, usable for signing.
    pub group: GroupPackage,
    /// Merged VSS commitments for the whole group.
    /// Use these to verify any participant's aggregate share via `verify_share`.
    pub vss_commits: Vec<[u8; 33]>,
}

/// One member's ECDH keyshare for a single target public key.
#[derive(Clone, Debug)]
pub struct EcdhEntry {
    /// The target public key this share is for.
    pub ecdh_pk: [u8; 33],
    /// 33-byte compressed ECDH keyshare point.
    pub keyshare: [u8; 33],
}

/// An ECDH package from one member, covering one or more target keys.
#[derive(Clone, Debug)]
pub struct EcdhPackage {
    /// The member's index.
    pub idx: u32,
    /// The quorum members used for Lagrange interpolation.
    pub members: Vec<u32>,
    /// One entry per target public key.
    pub entries: Vec<EcdhEntry>,
}
