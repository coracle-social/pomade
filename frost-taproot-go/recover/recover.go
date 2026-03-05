// Package recover provides share recovery functionality.
package recover

import (
	"math/big"
	"slices"

	"github.com/frost-taproot/frost-taproot-go/ecc"
	"github.com/frost-taproot/frost-taproot-go/poly"
	"github.com/frost-taproot/frost-taproot-go/types"
	"github.com/frost-taproot/frost-taproot-go/util"
	"github.com/frost-taproot/frost-taproot-go/vss"
)

// GenRecoveryShares generates recovery shares for a target participant.
func GenRecoveryShares(members []uint32, share *types.SecretShare, target uint32, threshold int, secrets [][32]byte) (types.SecretSharePackage, error) {
	if len(members) < threshold {
		return types.SecretSharePackage{}, &util.AssertionError{Message: "not enough members to meet threshold"}
	}

	sortedMembers := make([]uint32, len(members))
	copy(sortedMembers, members)
	slices.Sort(sortedMembers)

	shareIdx := poly.IndexToScalar(share.ID)
	targetIdx := poly.IndexToScalar(target)

	mbrs := make([]*big.Int, 0)
	for _, idx := range sortedMembers {
		if idx != share.ID {
			mbrs = append(mbrs, poly.IndexToScalar(idx))
		}
	}

	shareSeckey := ecc.ScalarFromBytes(share.Seckey)
	lgrngCoeff, err := poly.CalcLagrangeCoeff(mbrs, shareIdx, targetIdx)
	if err != nil {
		return types.SecretSharePackage{}, err
	}

	if lgrngCoeff.Sign() == 0 {
		return types.SecretSharePackage{}, &util.AssertionError{Message: "lagrange coefficient must be greater than zero"}
	}

	randCoeffs := vss.CreateShareCoeffs(secrets, threshold-1)
	coeffSum := big.NewInt(0)
	for _, c := range randCoeffs {
		coeffSum = ecc.ScalarAdd(coeffSum, c)
	}
	repairCoeff := ecc.ScalarSub(ecc.ScalarMul(lgrngCoeff, shareSeckey), coeffSum)

	repairShares := make([]*big.Int, len(randCoeffs)+1)
	for i, c := range randCoeffs {
		repairShares[i] = c
	}
	repairShares[len(randCoeffs)] = repairCoeff

	if len(sortedMembers) != len(repairShares) {
		return types.SecretSharePackage{}, &util.AssertionError{Message: "member count must equal threshold"}
	}

	vssCommits := vss.GetShareCommits(repairShares)

	sharesList := make([]types.SecretShare, len(sortedMembers))
	for i, idx := range sortedMembers {
		sharesList[i] = types.SecretShare{
			ID:     idx,
			Seckey: ecc.ScalarToBytes(repairShares[i]),
		}
	}

	return types.SecretSharePackage{
		ID:         share.ID,
		Shares:     sharesList,
		VssCommits: vssCommits,
	}, nil
}

// RecoverShare recovers a participant's share by summing recovery shares.
func RecoverShare(sharesList []types.SecretShare, id uint32) types.SecretShare {
	summed := big.NewInt(0)
	for _, s := range sharesList {
		summed = ecc.ScalarAdd(summed, ecc.ScalarFromBytes(s.Seckey))
	}
	return types.SecretShare{
		ID:     id,
		Seckey: ecc.ScalarToBytes(summed),
	}
}
