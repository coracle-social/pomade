// Package types defines the core data structures for FROST threshold signing.
package types

// PointState represents accumulated parity/tweak state for a group key.
type PointState struct {
	Parity [32]byte
	Point  [33]byte
	State  [32]byte
	Tweak  [32]byte
}

// SecretNonce represents a participant's secret nonces for one signing round.
type SecretNonce struct {
	ID       uint32
	BinderSn [32]byte
	HiddenSn [32]byte
}

// PublicNonce represents a participant's public nonce commitments for one signing round.
type PublicNonce struct {
	ID       uint32
	BinderPn [33]byte
	HiddenPn [33]byte
}

// CommitmentPackage combines secret + public nonce package for a participant.
type CommitmentPackage struct {
	ID       uint32
	BinderSn [32]byte
	HiddenSn [32]byte
	BinderPn [33]byte
	HiddenPn [33]byte
}

// SecretNonce returns the secret nonce part.
func (c *CommitmentPackage) SecretNonce() SecretNonce {
	return SecretNonce{
		ID:       c.ID,
		BinderSn: c.BinderSn,
		HiddenSn: c.HiddenSn,
	}
}

// PublicNonce returns the public nonce part.
func (c *CommitmentPackage) PublicNonce() PublicNonce {
	return PublicNonce{
		ID:       c.ID,
		BinderPn: c.BinderPn,
		HiddenPn: c.HiddenPn,
	}
}

// BindFactor represents per-participant binding factor.
type BindFactor struct {
	ID     uint32
	Factor [32]byte
}

// GroupKeyContext represents the group key and its tweaked state.
type GroupKeyContext struct {
	GroupPt PointState
	GroupPk [33]byte
	IntPt   *[33]byte
	IntPk   *[33]byte
	Tweak   *[32]byte
}

// GroupCommitContext contains everything derived from nonces and message.
type GroupCommitContext struct {
	BindFactors []BindFactor
	BindPrefix  []byte
	Challenge   [32]byte
	GroupPn     [33]byte
	Indexes     []uint32
	Message     []byte
	Pnonces     []PublicNonce
}

// GroupSigningCtx is the full signing context.
type GroupSigningCtx struct {
	GroupPt     PointState
	GroupPk     [33]byte
	IntPt       *[33]byte
	IntPk       *[33]byte
	Tweak       *[32]byte
	BindFactors []BindFactor
	BindPrefix  []byte
	Challenge   [32]byte
	GroupPn     [33]byte
	Indexes     []uint32
	Message     []byte
	Pnonces     []PublicNonce
}

// KeyContext extracts the key context.
func (g *GroupSigningCtx) KeyContext() GroupKeyContext {
	return GroupKeyContext{
		GroupPt: g.GroupPt,
		GroupPk: g.GroupPk,
		IntPt:   g.IntPt,
		IntPk:   g.IntPk,
		Tweak:   g.Tweak,
	}
}

// SecretShare represents a participant's secret share.
type SecretShare struct {
	ID     uint32
	Seckey [32]byte
}

// PublicShare represents a participant's public share.
type PublicShare struct {
	ID     uint32
	Pubkey [33]byte
}

// SecretShareSet represents a set of secret shares with VSS commitments.
type SecretShareSet struct {
	Shares     []SecretShare
	VssCommits [][33]byte
}

// DealerShareSet represents a dealer-produced share set with group public key.
type DealerShareSet struct {
	Shares     []SecretShare
	VssCommits [][33]byte
	GroupPk    [33]byte
}

// SecretSharePackage represents shares tagged with participant index.
type SecretSharePackage struct {
	ID         uint32
	Shares     []SecretShare
	VssCommits [][33]byte
}

// ShareSignature represents a partial signature from one participant.
type ShareSignature struct {
	ID     uint32
	Pubkey [33]byte
	Psig   [32]byte
}

// HasID is implemented by types that carry a participant index.
type HasID interface {
	GetID() uint32
}

// GetID returns the participant index for SecretShare.
func (s SecretShare) GetID() uint32 { return s.ID }

// GetID returns the participant index for PublicShare.
func (p PublicShare) GetID() uint32 { return p.ID }

// GetID returns the participant index for BindFactor.
func (b BindFactor) GetID() uint32 { return b.ID }

// GetID returns the participant index for PublicNonce.
func (p PublicNonce) GetID() uint32 { return p.ID }

// GetID returns the participant index for SecretNonce.
func (s SecretNonce) GetID() uint32 { return s.ID }

// GetID returns the participant index for CommitmentPackage.
func (c CommitmentPackage) GetID() uint32 { return c.ID }

// GetID returns the participant index for ShareSignature.
func (s ShareSignature) GetID() uint32 { return s.ID }
