// Package group provides high-level share set creation (trusted dealer).
package group

import (
	"github.com/frost-taproot/frost-taproot-go/shares"
	"github.com/frost-taproot/frost-taproot-go/types"
	"github.com/frost-taproot/frost-taproot-go/vss"
)

// CreateShareSet creates a set of secret shares and VSS commitments.
func CreateShareSet(threshold int, shareMax uint32, secrets [][32]byte) (types.SecretShareSet, error) {
	coeffs := vss.CreateShareCoeffs(secrets, threshold)
	sharesList, err := shares.CreateShares(coeffs, shareMax)
	if err != nil {
		return types.SecretShareSet{}, err
	}
	vssCommits := vss.GetShareCommits(coeffs)
	return types.SecretShareSet{
		Shares:     sharesList,
		VssCommits: vssCommits,
	}, nil
}

// CreateDealerSet creates a dealer share set with group public key.
func CreateDealerSet(threshold int, shareMax uint32, secrets [][32]byte) (types.DealerShareSet, error) {
	shareSet, err := CreateShareSet(threshold, shareMax, secrets)
	if err != nil {
		return types.DealerShareSet{}, err
	}
	return types.DealerShareSet{
		Shares:     shareSet.Shares,
		VssCommits: shareSet.VssCommits,
		GroupPk:    shareSet.VssCommits[0],
	}, nil
}
