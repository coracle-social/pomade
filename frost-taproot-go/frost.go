// Package frost_taproot provides FROST threshold signing for secp256k1.
//
// This package is a Go port of frost-taproot-rust, compatible with
// cmdcode/bifrost and frost-taproot-rust.
//
// The API is organized into subpackages:
//   - ecc: Elliptic curve operations
//   - types: Core data structures
//   - util: Utility functions
//   - poly: Polynomial operations
//   - vss: Verifiable secret sharing
//   - shares: Share creation and verification
//   - group: Group creation (trusted dealer)
//   - commit: Nonce commitments
//   - context: Signing context
//   - sign: Signing operations
//   - ecdh: Threshold ECDH
//   - recover: Share recovery
//   - refresh: Proactive secret sharing
//   - frost: High-level API
//
// For most use cases, use the frost subpackage which provides a
// simplified API similar to the TypeScript bifrost library.
package frost_taproot

import (
	"github.com/frost-taproot/frost-taproot-go/commit"
	"github.com/frost-taproot/frost-taproot-go/context"
	"github.com/frost-taproot/frost-taproot-go/ecc"
	"github.com/frost-taproot/frost-taproot-go/ecdh"
	"github.com/frost-taproot/frost-taproot-go/group"
	"github.com/frost-taproot/frost-taproot-go/helpers"
	"github.com/frost-taproot/frost-taproot-go/poly"
	"github.com/frost-taproot/frost-taproot-go/recover"
	"github.com/frost-taproot/frost-taproot-go/refresh"
	"github.com/frost-taproot/frost-taproot-go/shares"
	"github.com/frost-taproot/frost-taproot-go/sign"
	"github.com/frost-taproot/frost-taproot-go/types"
	"github.com/frost-taproot/frost-taproot-go/util"
	"github.com/frost-taproot/frost-taproot-go/vss"
)

// Re-export all packages
var (
	// ECC operations
	ModN               = ecc.ModN
	ScalarFromBytes    = ecc.ScalarFromBytes
	ScalarToBytes      = ecc.ScalarToBytes
	ScalarAdd          = ecc.ScalarAdd
	ScalarMul          = ecc.ScalarMul
	ScalarNeg          = ecc.ScalarNeg
	ScalarInvert       = ecc.ScalarInvert
	ScalarSub          = ecc.ScalarSub
	PowN               = ecc.PowN
	LiftX              = ecc.LiftX
	SerializePoint     = ecc.SerializePoint
	DeserializePoint   = ecc.DeserializePoint
	HasEvenY           = ecc.HasEvenY
	NegatePoint        = ecc.NegatePoint
	ElementAdd         = ecc.ElementAdd
	PointAdd           = ecc.PointAdd
	PointDouble        = ecc.PointDouble
	ScalarBaseMulti    = ecc.ScalarBaseMulti
	ScalarMulti        = ecc.ScalarMulti
	SerializeElement   = ecc.SerializeElement
	DeserializeElement = ecc.DeserializeElement
	SerializeScalarU32 = ecc.SerializeScalarU32
	RandomBytes        = ecc.RandomBytes
	RandomBytes32      = ecc.RandomBytes32

	// Hash functions
	H1      = ecc.H1
	H2      = ecc.H2
	H3      = ecc.H3
	H4      = ecc.H4
	H5      = ecc.H5
	TagHash = ecc.TagHash
	Hash340 = ecc.Hash340

	// Helpers
	GenerateSeckey        = helpers.GenerateSeckey
	GenerateNonce         = helpers.GenerateNonce
	GetPubkey             = helpers.GetPubkey
	TweakSeckey           = helpers.TweakSeckey
	TweakPubkey           = helpers.TweakPubkey
	GetChallenge          = helpers.GetChallenge
	ConvertPubkeyToBip340 = helpers.ConvertPubkeyToBip340
	ConvertPubkeyToEcdsa  = helpers.ConvertPubkeyToEcdsa

	// Polynomial operations
	EvaluateX         = poly.EvaluateX
	InterpolateRoot   = poly.InterpolateRoot
	InterpolateX      = poly.InterpolateX
	CalcLagrangeCoeff = poly.CalcLagrangeCoeff
	IndexToScalar     = poly.IndexToScalar

	// VSS operations
	CreateShareCoeffs = vss.CreateShareCoeffs
	GetShareCommits   = vss.GetShareCommits
	MergeShareCommits = vss.MergeShareCommits

	// Share operations
	CreateShares       = shares.CreateShares
	CombineShares      = shares.CombineShares
	CombineSet         = shares.CombineSet
	MergeShares        = shares.MergeShares
	VerifyShare        = shares.VerifyShare
	DeriveSharesSecret = shares.DeriveSharesSecret

	// Group operations
	CreateShareSet  = group.CreateShareSet
	CreateDealerSet = group.CreateDealerSet

	// Commit operations
	GetNonceIDs      = commit.GetNonceIDs
	GetCommitsPrefix = commit.GetCommitsPrefix
	GetGroupPrefix   = commit.GetGroupPrefix
	GetBindFactor    = commit.GetBindFactor
	GetGroupBinders  = commit.GetGroupBinders
	GetGroupPubnonce = commit.GetGroupPubnonce
	CreateCommitPkg  = commit.CreateCommitPkg
	GetCommitPkg     = commit.GetCommitPkg

	// Context operations
	GetPointState         = context.GetPointState
	GetGroupKeyContext    = context.GetGroupKeyContext
	GetGroupCommitContext = context.GetGroupCommitContext
	GetGroupSigningCtx    = context.GetGroupSigningCtx

	// Signing operations
	SignMsg            = sign.SignMsg
	CombinePartialSigs = sign.CombinePartialSigs
	VerifyPartialSig   = sign.VerifyPartialSig
	VerifyFinalSig     = sign.VerifyFinalSig

	// ECDH operations
	CreateEcdhShare  = ecdh.CreateEcdhShare
	DeriveEcdhSecret = ecdh.DeriveEcdhSecret

	// Recovery operations
	GenRecoveryShares = recover.GenRecoveryShares
	RecoverShare      = recover.RecoverShare

	// Refresh operations
	GenRefreshShares = refresh.GenRefreshShares
	RefreshShare     = refresh.RefreshShare

	// Utility functions
	OK         = util.OK
	HexToBytes = util.HexToBytes
	HexTo32    = util.HexTo32
	HexTo33    = util.HexTo33
	BytesToHex = util.BytesToHex
)

// Re-export types
type (
	PointState         = types.PointState
	SecretNonce        = types.SecretNonce
	PublicNonce        = types.PublicNonce
	CommitmentPackage  = types.CommitmentPackage
	BindFactor         = types.BindFactor
	GroupKeyContext    = types.GroupKeyContext
	GroupCommitContext = types.GroupCommitContext
	GroupSigningCtx    = types.GroupSigningCtx
	SecretShare        = types.SecretShare
	PublicShare        = types.PublicShare
	SecretShareSet     = types.SecretShareSet
	DealerShareSet     = types.DealerShareSet
	SecretSharePackage = types.SecretSharePackage
	ShareSignature     = types.ShareSignature
	Point              = ecc.Point
	HasID              = types.HasID
)

// Error types
type (
	RecordNotFoundError  = util.RecordNotFoundError
	AssertionError       = util.AssertionError
	InvalidPointError    = util.InvalidPointError
	BothPointsNullError  = util.BothPointsNullError
	ScalarInversionError = util.ScalarInversionError
)
