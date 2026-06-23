// Package vss provides verifiable secret sharing functionality.
package vss

import (
	"math/big"

	"github.com/frost-taproot/frost-taproot-go/ecc"
	"github.com/frost-taproot/frost-taproot-go/util"
)

// CreateShareCoeffs creates polynomial coefficients for Shamir secret sharing.
func CreateShareCoeffs(secrets [][32]byte, threshold int) []*big.Int {
	coeffs := make([]*big.Int, 0, threshold)
	for i := 0; i < threshold; i++ {
		var coeff *big.Int
		if i < len(secrets) {
			coeff = ecc.ScalarFromBytes(secrets[i])
		} else {
			random := ecc.RandomBytes32()
			coeff = ecc.ScalarFromBytes(random)
		}
		coeffs = append(coeffs, coeff)
	}
	return coeffs
}

// GetShareCommits computes VSS commitments: one compressed public key per coefficient.
func GetShareCommits(coeffs []*big.Int) [][33]byte {
	commits := make([][33]byte, len(coeffs))
	for i, c := range coeffs {
		// c is a secret polynomial coefficient, so commit to it (c*G) in
		// constant time wrt the secret (see ecc.ScalarBaseMultiCT).
		commits[i] = ecc.ScalarBaseMultiCT(ecc.ScalarToBytes(c))
	}
	return commits
}

// MergeShareCommits merges two sets of VSS commitments by adding corresponding points.
func MergeShareCommits(commitsA, commitsB [][33]byte) ([][33]byte, error) {
	if err := util.EqualArrSize(commitsA, commitsB); err != nil {
		return nil, err
	}
	result := make([][33]byte, len(commitsA))
	for i := range commitsA {
		pa, err := ecc.LiftX(commitsA[i][:])
		if err != nil {
			return nil, err
		}
		pb, err := ecc.LiftX(commitsB[i][:])
		if err != nil {
			return nil, err
		}
		pc := ecc.PointAdd(pa, pb)
		result[i] = ecc.SerializePoint(pc)
	}
	return result, nil
}
