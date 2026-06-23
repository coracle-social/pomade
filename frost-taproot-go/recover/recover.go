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
	// The lagrange coefficient is public, but the share seckey and the random VSS
	// coefficients are secret, so the multiply, the running sum and the final
	// subtraction keep a secret as base and run in constant time wrt the secret
	// (see ecc.ScalarMulCT / ecc.ScalarAddCT / ecc.ScalarNegCT).
	var coeffSum [32]byte
	for i, c := range randCoeffs {
		if i == 0 {
			coeffSum = ecc.ScalarToBytes(c)
		} else {
			coeffSum = ecc.ScalarAddCT(coeffSum, ecc.ScalarToBytes(c))
		}
	}
	lagrangeShare := ecc.ScalarMulCT(ecc.ScalarToBytes(shareSeckey), ecc.ScalarToBytes(lgrngCoeff))
	repairCoeffBytes := ecc.ScalarAddCT(lagrangeShare, ecc.ScalarNegCT(coeffSum))
	repairCoeff := ecc.ScalarFromBytes(repairCoeffBytes)

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

// RecoverShare recovers a participant's share by summing recovery shares. The
// addition runs in constant time wrt the secret recovery shares (ecc.ScalarAddCT).
func RecoverShare(sharesList []types.SecretShare, id uint32) types.SecretShare {
	var summed [32]byte
	for i, s := range sharesList {
		if i == 0 {
			summed = s.Seckey
		} else {
			summed = ecc.ScalarAddCT(summed, s.Seckey)
		}
	}
	return types.SecretShare{
		ID:     id,
		Seckey: ecc.ScalarToBytes(ecc.ScalarFromBytes(summed)),
	}
}
