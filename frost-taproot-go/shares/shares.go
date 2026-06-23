// Package shares provides secret share creation and verification.
package shares

import (
	"math/big"

	"github.com/frost-taproot/frost-taproot-go/ecc"
	"github.com/frost-taproot/frost-taproot-go/poly"
	"github.com/frost-taproot/frost-taproot-go/types"
	"github.com/frost-taproot/frost-taproot-go/util"
)

// CreateShares creates secret shares by evaluating polynomial at indices 1..=count.
func CreateShares(coeffs []*big.Int, count uint32) ([]types.SecretShare, error) {
	shares := make([]types.SecretShare, 0, count)
	for i := uint32(1); i <= count; i++ {
		x := poly.IndexToScalar(i)
		scalar, err := poly.EvaluateX(coeffs, x)
		if err != nil {
			return nil, err
		}
		shares = append(shares, types.SecretShare{
			ID:     i,
			Seckey: ecc.ScalarToBytes(scalar),
		})
	}
	return shares, nil
}

// CombineShares sums a list of secret shares into a single scalar. The addition
// runs in constant time wrt the secret shares (see ecc.ScalarAddCT).
func CombineShares(shares []types.SecretShare) [32]byte {
	if len(shares) == 0 {
		return [32]byte{}
	}
	secret := shares[0].Seckey
	for _, s := range shares[1:] {
		secret = ecc.ScalarAddCT(secret, s.Seckey)
	}
	return ecc.ScalarToBytes(ecc.ScalarFromBytes(secret))
}

// CombineSet combines shares with the same ID into one share.
func CombineSet(shares []types.SecretShare) (types.SecretShare, error) {
	ids := make([]uint32, len(shares))
	for i, s := range shares {
		ids[i] = s.ID
	}
	if err := util.IsEqualSet(ids); err != nil {
		return types.SecretShare{}, err
	}
	return types.SecretShare{
		ID:     shares[0].ID,
		Seckey: CombineShares(shares),
	}, nil
}

// MergeShares merges two lists of shares by combining matching indices.
func MergeShares(sharesA, sharesB []types.SecretShare) ([]types.SecretShare, error) {
	if err := util.EqualArrSize(sharesA, sharesB); err != nil {
		return nil, err
	}
	result := make([]types.SecretShare, len(sharesA))
	for i, curr := range sharesA {
		var aux *types.SecretShare
		for _, s := range sharesB {
			if s.ID == curr.ID {
				aux = &s
				break
			}
		}
		if aux == nil {
			return nil, &util.RecordNotFoundError{Idx: curr.ID}
		}
		combined, err := CombineSet([]types.SecretShare{curr, *aux})
		if err != nil {
			return nil, err
		}
		result[i] = combined
	}
	return result, nil
}

// VerifyShare verifies a secret share against VSS commitments.
func VerifyShare(commits [][33]byte, share *types.SecretShare, threshold int) (bool, error) {
	// share.Seckey is secret, so derive its public point (seckey*G) in constant
	// time wrt the secret (see ecc.ScalarBaseMultiCT).
	siBytes := ecc.ScalarBaseMultiCT(share.Seckey)
	si, err := ecc.LiftX(siBytes[:])
	if err != nil {
		return false, err
	}

	if threshold == 0 {
		return false, &util.AssertionError{Message: "no commits"}
	}
	if threshold > len(commits) {
		return false, &util.AssertionError{Message: "threshold exceeds commit count"}
	}

	var sip *ecc.Point
	for j := 0; j < threshold; j++ {
		point, err := ecc.LiftX(commits[j][:])
		if err != nil {
			return false, err
		}
		exp := ecc.PowN(uint64(share.ID), uint64(j))
		prod := ecc.ScalarMulti(point, exp)
		var addErr error
		sip, addErr = ecc.ElementAdd(sip, prod)
		if addErr != nil {
			return false, addErr
		}
	}

	return si.X.Cmp(sip.X) == 0, nil
}

// DeriveSharesSecret recovers the group secret by Lagrange interpolation.
func DeriveSharesSecret(shares []types.SecretShare) ([32]byte, error) {
	points := make([][2]*big.Int, len(shares))
	for i, s := range shares {
		points[i] = [2]*big.Int{
			poly.IndexToScalar(s.ID),
			ecc.ScalarFromBytes(s.Seckey),
		}
	}
	secret, err := poly.InterpolateRoot(points)
	if err != nil {
		return [32]byte{}, err
	}
	return ecc.ScalarToBytes(secret), nil
}
