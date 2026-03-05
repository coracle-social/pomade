// Mirrors ref/frost/src/types/sign.ts

/// A partial signature produced by one participant.
#[derive(Clone, Debug)]
pub struct ShareSignature {
    pub idx: u32,
    pub pubkey: [u8; 33],
    pub psig: [u8; 32],
}
