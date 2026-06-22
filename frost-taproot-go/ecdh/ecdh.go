// Package ecdh provides threshold ECDH key derivation.
package ecdh

import (
	"math/big"

	"github.com/frost-taproot/frost-taproot-go/ecc"
	"github.com/frost-taproot/frost-taproot-go/poly"
	"github.com/frost-taproot/frost-taproot-go/types"
	"github.com/frost-taproot/frost-taproot-go/util"
)

// CreateEcdhShare computes an ECDH share contribution.
func CreateEcdhShare(members []uint32, share *types.SecretShare, pubkey []byte) (types.PublicShare, error) {
	mbrs := make([]*big.Int, 0, len(members))
	for _, idx := range members {
		if idx != share.ID {
			mbrs = append(mbrs, poly.IndexToScalar(idx))
		}
	}

	idx := poly.IndexToScalar(share.ID)
	point, err := ecc.LiftX(pubkey)
	if err != nil {
		return types.PublicShare{}, err
	}

	lCoeff, err := poly.CalcLagrangeCoeff(mbrs, idx, big.NewInt(0))
	if err != nil {
		return types.PublicShare{}, err
	}
	// pCoeff = lagrange * share, and ecdhPt = pCoeff * point. Both multiplications
	// are constant time with respect to the secret share: the lagrange coefficient
	// is public, the input point is attacker-supplied, so a variable-time scalar
	// mult here would leak the share to a timing attacker on the /ecdh endpoint.
	pCoeff := ecc.ScalarMulCT(share.Seckey, ecc.ScalarToBytes(lCoeff))
	ecdhPk := ecc.ScalarMultiCT(ecc.SerializePoint(point), pCoeff)

	return types.PublicShare{
		ID:     share.ID,
		Pubkey: ecdhPk,
	}, nil
}

// DeriveEcdhSecret derives the shared ECDH secret by summing all shares.
func DeriveEcdhSecret(shares []types.PublicShare) ([33]byte, error) {
	var point *ecc.Point
	for _, share := range shares {
		pt, err := ecc.LiftX(share.Pubkey[:])
		if err != nil {
			return [33]byte{}, err
		}
		var err2 error
		point, err2 = ecc.ElementAdd(point, pt)
		if err2 != nil {
			return [33]byte{}, err2
		}
	}

	if point == nil {
		return [33]byte{}, &util.BothPointsNullError{}
	}
	return ecc.SerializePoint(point), nil
}
