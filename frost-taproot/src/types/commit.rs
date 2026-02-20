// Mirrors ref/frost/src/types/commit.ts

/// A participant's secret nonces for one signing round.
#[derive(Clone, Debug)]
pub struct SecretNonce {
    pub idx: u32,
    pub binder_sn: [u8; 32],
    pub hidden_sn: [u8; 32],
}

/// A participant's public nonce commitments for one signing round.
#[derive(Clone, Debug)]
pub struct PublicNonce {
    pub idx: u32,
    pub binder_pn: [u8; 33],
    pub hidden_pn: [u8; 33],
}

/// Combined secret + public nonce package for a participant.
/// Mirrors `CommitmentPackage = SecretNonce & PublicNonce`.
#[derive(Clone, Debug)]
pub struct CommitmentPackage {
    pub idx: u32,
    pub binder_sn: [u8; 32],
    pub hidden_sn: [u8; 32],
    pub binder_pn: [u8; 33],
    pub hidden_pn: [u8; 33],
}

impl CommitmentPackage {
    pub fn secret_nonce(&self) -> SecretNonce {
        SecretNonce {
            idx: self.idx,
            binder_sn: self.binder_sn,
            hidden_sn: self.hidden_sn,
        }
    }

    pub fn public_nonce(&self) -> PublicNonce {
        PublicNonce {
            idx: self.idx,
            binder_pn: self.binder_pn,
            hidden_pn: self.hidden_pn,
        }
    }
}

/// Per-participant binding factor.
#[derive(Clone, Debug)]
pub struct BindFactor {
    pub idx: u32,
    pub factor: [u8; 32],
}
