// Mirrors ref/frost/src/types/ecc.ts

use k256::{ProjectivePoint, Scalar};

/// Accumulated parity/tweak state for a group key.
/// Mirrors `PointState` in the TS implementation.
#[derive(Clone, Debug)]
pub struct PointState {
    /// Current parity factor (+1 or -1 as a Scalar).
    pub parity: Scalar,
    /// The (possibly tweaked) point.
    pub point: ProjectivePoint,
    /// Accumulated state (product of parities).
    pub state: Scalar,
    /// Accumulated tweak value.
    pub tweak: Scalar,
}
