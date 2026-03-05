// Package frost provides high-level FROST threshold signing API.
package frost

import (
	"math/big"

	"github.com/frost-taproot/frost-taproot-go/ecc"
	"github.com/frost-taproot/frost-taproot-go/poly"
	"github.com/frost-taproot/frost-taproot-go/shares"
	"github.com/frost-taproot/frost-taproot-go/types"
	"github.com/frost-taproot/frost-taproot-go/util"
	"github.com/frost-taproot/frost-taproot-go/vss"
)

// DkgRound1 generates Round 1 polynomial and commitments.
func DkgRound1(idx uint32, threshold int, secrets [][32]byte) ([][32]byte, DkgCommitPackage) {
	coeffs := vss.CreateShareCoeffs(secrets, threshold)
	vssCommits := vss.GetShareCommits(coeffs)

	secretCoeffs := make([][32]byte, len(coeffs))
	for i, c := range coeffs {
		secretCoeffs[i] = ecc.ScalarToBytes(c)
	}

	return secretCoeffs, DkgCommitPackage{Idx: idx, VssCommits: vssCommits}
}

// DkgRound2 generates the private share for one recipient.
func DkgRound2(senderIdx uint32, secretCoeffs [][32]byte, recipientIdx uint32) (DkgSharePackage, error) {
	coeffs := make([]*big.Int, len(secretCoeffs))
	for i, c := range secretCoeffs {
		coeffs[i] = ecc.ScalarFromBytes(c)
	}
	x := poly.IndexToScalar(recipientIdx)
	shareScalar, err := poly.EvaluateX(coeffs, x)
	if err != nil {
		return DkgSharePackage{}, err
	}

	seckeyBytes := ecc.ScalarToBytes(shareScalar)

	return DkgSharePackage{
		SenderIdx:    senderIdx,
		RecipientIdx: recipientIdx,
		Seckey:       seckeyBytes,
	}, nil
}

// VerifyDkgShare verifies a share against sender's VSS commitments.
func VerifyDkgShare(share *DkgSharePackage, senderCommits *DkgCommitPackage, threshold int) (bool, error) {
	lowShare := types.SecretShare{
		ID:     share.RecipientIdx,
		Seckey: share.Seckey,
	}
	return shares.VerifyShare(senderCommits.VssCommits, &lowShare, threshold)
}

// DkgFinalize finalizes DKG and derives the group key.
func DkgFinalize(myIdx uint32, myCoeffs [][32]byte, received []DkgSharePackage, allCommits []DkgCommitPackage, threshold int) (DkgOutput, error) {
	// Validate all received shares
	for _, pkg := range received {
		var senderCommits *DkgCommitPackage
		for i := range allCommits {
			if allCommits[i].Idx == pkg.SenderIdx {
				senderCommits = &allCommits[i]
				break
			}
		}
		if senderCommits == nil {
			return DkgOutput{}, &util.RecordNotFoundError{Idx: pkg.SenderIdx}
		}
		ok, err := VerifyDkgShare(&pkg, senderCommits, threshold)
		if err != nil {
			return DkgOutput{}, err
		}
		if !ok {
			return DkgOutput{}, &util.AssertionError{Message: "DKG share failed VSS verification"}
		}
	}

	// Compute own share
	ownSharePkg, err := DkgRound2(myIdx, myCoeffs, myIdx)
	if err != nil {
		return DkgOutput{}, err
	}
	ownShare := types.SecretShare{
		ID:     myIdx,
		Seckey: ownSharePkg.Seckey,
	}

	// Aggregate shares
	allShares := make([]types.SecretShare, 0, len(received)+1)
	allShares = append(allShares, ownShare)
	for _, pkg := range received {
		allShares = append(allShares, types.SecretShare{
			ID:     myIdx,
			Seckey: pkg.Seckey,
		})
	}
	aggregate, err := shares.CombineSet(allShares)
	if err != nil {
		return DkgOutput{}, err
	}

	// Sort commits by idx
	sortedCommits := make([]DkgCommitPackage, len(allCommits))
	copy(sortedCommits, allCommits)
	for i := 0; i < len(sortedCommits); i++ {
		for j := i + 1; j < len(sortedCommits); j++ {
			if sortedCommits[j].Idx < sortedCommits[i].Idx {
				sortedCommits[i], sortedCommits[j] = sortedCommits[j], sortedCommits[i]
			}
		}
	}

	// Derive group public key
	firstCommits := make([][33]byte, len(sortedCommits))
	for i, c := range sortedCommits {
		firstCommits[i] = c.VssCommits[0]
	}
	groupPk, err := sumPoints(firstCommits)
	if err != nil {
		return DkgOutput{}, err
	}

	// Merge VSS commits
	var groupVssCommits [][33]byte
	for _, c := range sortedCommits {
		if groupVssCommits == nil {
			groupVssCommits = c.VssCommits
		} else {
			groupVssCommits, err = vss.MergeShareCommits(groupVssCommits, c.VssCommits)
			if err != nil {
				return DkgOutput{}, err
			}
		}
	}

	// Build member packages
	members := make([]MemberPackage, len(sortedCommits))
	for i, c := range sortedCommits {
		sharePubkey, err := evalVssPubkey(groupVssCommits, c.Idx)
		if err != nil {
			return DkgOutput{}, err
		}
		members[i] = MemberPackage{
			Idx:        c.Idx,
			Pubkey:     sharePubkey,
			IdentityPk: &c.VssCommits[0],
		}
	}

	grp := GroupPackage{
		GroupPk:   groupPk,
		Threshold: threshold,
		Members:   members,
	}

	return DkgOutput{
		Share: SharePackage{
			Idx:    myIdx,
			Seckey: aggregate.Seckey,
		},
		Group:      grp,
		VssCommits: groupVssCommits,
	}, nil
}

func sumPoints(points [][33]byte) ([33]byte, error) {
	if len(points) == 0 {
		return [33]byte{}, &util.AssertionError{Message: "cannot sum empty point list"}
	}
	acc, err := ecc.LiftX(points[0][:])
	if err != nil {
		return [33]byte{}, err
	}
	for _, p := range points[1:] {
		pt, err := ecc.LiftX(p[:])
		if err != nil {
			return [33]byte{}, err
		}
		acc = ecc.PointAdd(acc, pt)
	}
	return ecc.SerializePoint(acc), nil
}

func evalVssPubkey(commits [][33]byte, idx uint32) ([33]byte, error) {
	if len(commits) == 0 {
		return [33]byte{}, &util.AssertionError{Message: "no VSS commits"}
	}
	var acc *ecc.Point
	for k, commit := range commits {
		point, err := ecc.LiftX(commit[:])
		if err != nil {
			return [33]byte{}, err
		}
		exp := ecc.PowN(uint64(idx), uint64(k))
		term := ecc.ScalarMulti(point, exp)
		if acc == nil {
			acc = term
		} else {
			acc = ecc.PointAdd(acc, term)
		}
	}
	return ecc.SerializePoint(acc), nil
}
