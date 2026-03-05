// Package commit provides commitment package creation and management.
package commit

import (
	"github.com/frost-taproot/frost-taproot-go/ecc"
	"github.com/frost-taproot/frost-taproot-go/helpers"
	"github.com/frost-taproot/frost-taproot-go/types"
	"github.com/frost-taproot/frost-taproot-go/util"
)

// GetNonceIDs extracts participant IDs from public nonces.
func GetNonceIDs(pnonces []types.PublicNonce) []uint32 {
	ids := make([]uint32, len(pnonces))
	for i, pn := range pnonces {
		ids[i] = pn.ID
	}
	return ids
}

// GetCommitsPrefix encodes all public nonces into a sorted byte prefix.
func GetCommitsPrefix(pnonces []types.PublicNonce) []byte {
	// Sort by ID (create copy to avoid modifying original)
	sorted := make([]types.PublicNonce, len(pnonces))
	copy(sorted, pnonces)
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j].ID < sorted[i].ID {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	out := make([]byte, 0, len(sorted)*(32+33+33))
	for _, pn := range sorted {
		scalarBytes := ecc.SerializeScalarU32(pn.ID)
		out = append(out, scalarBytes[:]...)
		out = append(out, pn.HiddenPn[:]...)
		out = append(out, pn.BinderPn[:]...)
	}
	return out
}

// GetGroupPrefix builds the group signing prefix: group_pk || H4(msg) || H5(commit_list).
func GetGroupPrefix(pnonces []types.PublicNonce, groupPk [33]byte, message []byte) []byte {
	msgHash := ecc.H4(message)
	commitList := GetCommitsPrefix(pnonces)
	commitHash := ecc.H5(commitList)

	out := make([]byte, 0, 33+32+32)
	out = append(out, groupPk[:]...)
	out = append(out, msgHash[:]...)
	out = append(out, commitHash[:]...)
	return out
}

// GetBindFactor looks up the binding factor for a participant.
func GetBindFactor(binders []types.BindFactor, idx uint32) ([32]byte, error) {
	for _, b := range binders {
		if b.ID == idx {
			return b.Factor, nil
		}
	}
	return [32]byte{}, &util.RecordNotFoundError{Idx: idx}
}

// GetGroupBinders computes per-participant binding factors.
func GetGroupBinders(pnonces []types.PublicNonce, prefix []byte) []types.BindFactor {
	factors := make([]types.BindFactor, len(pnonces))
	for i, pn := range pnonces {
		scalarBytes := ecc.SerializeScalarU32(pn.ID)
		rhoInput := make([]byte, 0, len(prefix)+32)
		rhoInput = append(rhoInput, prefix...)
		rhoInput = append(rhoInput, scalarBytes[:]...)
		factor := ecc.H1(rhoInput)
		factors[i] = types.BindFactor{
			ID:     pn.ID,
			Factor: factor,
		}
	}
	return factors
}

// GetGroupPubnonce computes the group public nonce.
func GetGroupPubnonce(pnonces []types.PublicNonce, binders []types.BindFactor) ([33]byte, error) {
	var groupCommit *ecc.Point

	for _, pn := range pnonces {
		hiddenElem, err := ecc.LiftX(pn.HiddenPn[:])
		if err != nil {
			return [33]byte{}, err
		}
		bindingElem, err := ecc.LiftX(pn.BinderPn[:])
		if err != nil {
			return [33]byte{}, err
		}
		bindFactorBytes, err := GetBindFactor(binders, pn.ID)
		if err != nil {
			return [33]byte{}, err
		}
		bindFactor := ecc.ScalarFromBytes(bindFactorBytes)
		factoredElem := ecc.ScalarMulti(bindingElem, bindFactor)
		groupCommit, err = ecc.ElementAdd(groupCommit, hiddenElem)
		if err != nil {
			return [33]byte{}, err
		}
		groupCommit, err = ecc.ElementAdd(groupCommit, factoredElem)
		if err != nil {
			return [33]byte{}, err
		}
	}

	if groupCommit == nil {
		return [33]byte{}, &util.BothPointsNullError{}
	}
	return ecc.SerializePoint(groupCommit), nil
}

// CreateCommitPkg creates a commitment package for a signing session.
func CreateCommitPkg(secretShare *types.SecretShare, hiddenSeed, binderSeed *[32]byte) types.CommitmentPackage {
	binderSn := helpers.GenerateNonce(secretShare.Seckey, binderSeed)
	hiddenSn := helpers.GenerateNonce(secretShare.Seckey, hiddenSeed)
	binderPn := helpers.GetPubkey(binderSn)
	hiddenPn := helpers.GetPubkey(hiddenSn)
	return types.CommitmentPackage{
		ID:       secretShare.ID,
		BinderSn: binderSn,
		HiddenSn: hiddenSn,
		BinderPn: binderPn,
		HiddenPn: hiddenPn,
	}
}

// GetCommitPkg finds a commitment package for a given share.
func GetCommitPkg(commits []types.CommitmentPackage, share *types.SecretShare) (types.CommitmentPackage, error) {
	for _, c := range commits {
		if c.ID == share.ID {
			return c, nil
		}
	}
	return types.CommitmentPackage{}, &util.RecordNotFoundError{Idx: share.ID}
}
