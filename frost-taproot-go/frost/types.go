// Package frost provides high-level FROST threshold signing API.
package frost

// SharePackage represents a member's secret share.
type SharePackage struct {
	Idx    uint32
	Seckey [32]byte
}

// MemberPackage represents a member's public identity.
type MemberPackage struct {
	Idx        uint32
	Pubkey     [33]byte
	IdentityPk *[33]byte
}

// GroupPackage represents the group's public state.
type GroupPackage struct {
	GroupPk   [33]byte
	Threshold int
	Members   []MemberPackage
}

// DealerPackage is the output of trusted dealer key generation.
type DealerPackage struct {
	Group  GroupPackage
	Shares []SharePackage
}

// PublicNonce represents a public nonce commitment.
type PublicNonce struct {
	BinderPn [33]byte
	HiddenPn [33]byte
}

// DerivedNonce includes a derivation code for secret re-derivation.
type DerivedNonce struct {
	BinderPn [33]byte
	HiddenPn [33]byte
	Code     [32]byte
}

// MemberNonce is a derived nonce with member index.
type MemberNonce struct {
	Idx      uint32
	BinderPn [33]byte
	HiddenPn [33]byte
	Code     [32]byte
}

// SecretNoncePair is the secret nonce re-derived from code.
type SecretNoncePair struct {
	Code     [32]byte
	BinderSn [32]byte
	HiddenSn [32]byte
}

// SignSession represents a signing session.
type SignSession struct {
	Sid      [32]byte
	GroupPk  [33]byte
	Members  []uint32
	Messages []SignMessage
	Nonces   []MemberNonce
}

// SignMessage represents a message with optional tweaks.
type SignMessage struct {
	Message []byte
	Tweaks  [][32]byte
}

// PartialSig represents a partial signature for one message.
type PartialSig struct {
	Message []byte
	Psig    [32]byte
}

// PartialSigPackage represents partial signatures from one member.
type PartialSigPackage struct {
	Idx    uint32
	Pubkey [33]byte
	Sid    [32]byte
	Psigs  []PartialSig
}

// Signature represents a completed BIP340 signature.
type Signature struct {
	Message []byte
	Pubkey  [33]byte
	Sig     [64]byte
}

// DkgPop is a Schnorr proof of possession of the secret behind VssCommits[0].
//
// It proves knowledge of a_i0 such that VssCommits[0] = a_i0*G, bound to the
// participant index. Without it, a participant broadcasting last can choose
// VssCommits[0] as a function of the others' commitments (a point whose discrete
// log it does not know) and steer the summed group key — a rogue-key attack. A
// crafted commitment has no valid proof, so DKG rejects it.
type DkgPop struct {
	R [33]byte // compressed commitment point R = k*G
	Z [32]byte // response scalar z = k + e*a_i0 (mod n)
}

// DkgCommitPackage represents Round 1 broadcast.
type DkgCommitPackage struct {
	Idx        uint32
	VssCommits [][33]byte
	// Pop proves possession of the constant-term secret a_i0 behind
	// VssCommits[0]. Verified before the commitment is folded into the group
	// key, which is what closes the rogue-key attack.
	Pop DkgPop
}

// DkgSharePackage represents Round 2 private message.
type DkgSharePackage struct {
	SenderIdx    uint32
	RecipientIdx uint32
	Seckey       [32]byte
}

// DkgOutput represents a participant's DKG result.
type DkgOutput struct {
	Share      SharePackage
	Group      GroupPackage
	VssCommits [][33]byte
}

// EcdhEntry represents one ECDH keyshare.
type EcdhEntry struct {
	EcdhPk   [33]byte
	Keyshare [33]byte
}

// EcdhPackage represents ECDH contributions from one member.
type EcdhPackage struct {
	Idx     uint32
	Members []uint32
	Entries []EcdhEntry
}
