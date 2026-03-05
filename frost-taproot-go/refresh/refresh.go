// Package refresh provides proactive secret sharing functionality.
package refresh

import (
	"math/big"

	"github.com/frost-taproot/frost-taproot-go/shares"
	"github.com/frost-taproot/frost-taproot-go/types"
	"github.com/frost-taproot/frost-taproot-go/vss"
)

// GenRefreshShares generates refresh shares with zero constant term.
func GenRefreshShares(index uint32, threshold int, shareMax uint32, secrets [][32]byte) (types.SecretSharePackage, error) {
	// Auxiliary coefficients (threshold - 1, no constant term)
	subCoeffs := vss.CreateShareCoeffs(secrets, threshold-1)
	// Prepend zero as constant term
	coeffs := make([]*big.Int, 0, threshold)
	coeffs = append(coeffs, big.NewInt(0))
	for _, c := range subCoeffs {
		coeffs = append(coeffs, c)
	}

	sharesList, err := shares.CreateShares(coeffs, shareMax)
	if err != nil {
		return types.SecretSharePackage{}, err
	}
	vssCommits := vss.GetShareCommits(subCoeffs)

	return types.SecretSharePackage{
		ID:         index,
		Shares:     sharesList,
		VssCommits: vssCommits,
	}, nil
}

// RefreshShare applies refresh shares to a current share.
func RefreshShare(refreshShares []types.SecretShare, currentShare *types.SecretShare) (types.SecretShare, error) {
	all := make([]types.SecretShare, 0, len(refreshShares)+1)
	all = append(all, *currentShare)
	all = append(all, refreshShares...)
	return shares.CombineSet(all)
}
