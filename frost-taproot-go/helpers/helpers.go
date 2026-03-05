// Package helpers provides helper functions for FROST operations.
package helpers

import (
	"math/big"

	"github.com/frost-taproot/frost-taproot-go/ecc"
	"github.com/frost-taproot/frost-taproot-go/util"
)

// GenerateSeckey generates a secret key from optional auxiliary bytes using H3.
func GenerateSeckey(aux *[32]byte) [32]byte {
	var auxBytes [32]byte
	if aux != nil {
		auxBytes = *aux
	} else {
		auxBytes = ecc.RandomBytes32()
	}
	return ecc.H3(auxBytes[:])
}

// GenerateNonce generates a secret nonce from secret and optional aux seed.
func GenerateNonce(secret [32]byte, auxSeed *[32]byte) [32]byte {
	var aux [32]byte
	if auxSeed != nil {
		aux = *auxSeed
	} else {
		aux = ecc.RandomBytes32()
	}
	input := make([]byte, 64)
	copy(input[:32], aux[:])
	copy(input[32:], secret[:])
	return ecc.H3(input)
}

// GetPubkey derives a compressed public key from a secret key.
func GetPubkey(secret [32]byte) [33]byte {
	scalar := ecc.ScalarFromBytes(secret)
	point := ecc.ScalarBaseMulti(scalar)
	return ecc.SerializePoint(point)
}

// TweakSeckey tweaks a secret key: (seckey * tweak) mod N.
func TweakSeckey(seckey, tweak [32]byte) [32]byte {
	tweakScalar := ecc.ScalarFromBytes(tweak)
	secret := ecc.ScalarFromBytes(seckey)
	return ecc.ScalarToBytes(ecc.ScalarMul(secret, tweakScalar))
}

// TweakPubkey tweaks a public key: pubkey_point * tweak.
func TweakPubkey(pubkey []byte, tweak [32]byte) ([33]byte, error) {
	tweakScalar := ecc.ScalarFromBytes(tweak)
	point, err := ecc.LiftX(pubkey)
	if err != nil {
		return [33]byte{}, err
	}
	tweaked := ecc.ScalarMulti(point, tweakScalar)
	return ecc.SerializePoint(tweaked), nil
}

// GetChallenge computes BIP340-style challenge hash.
func GetChallenge(pnonce, pubkey []byte, message []byte) (*big.Int, error) {
	grpPn, err := ConvertPubkeyToBip340(pnonce)
	if err != nil {
		return nil, err
	}
	grpPk, err := ConvertPubkeyToBip340(pubkey)
	if err != nil {
		return nil, err
	}
	if len(grpPn) != 32 {
		return nil, &util.AssertionError{Message: "pnonce must be 32 bytes after conversion"}
	}
	if len(grpPk) != 32 {
		return nil, &util.AssertionError{Message: "pubkey must be 32 bytes after conversion"}
	}
	digest := ecc.Hash340("BIP0340/challenge", [][]byte{grpPn, grpPk, message})
	return ecc.ScalarFromBytes(digest), nil
}

// ConvertPubkeyToBip340 converts a pubkey to BIP340 format (x-only, 32 bytes).
func ConvertPubkeyToBip340(pubkey []byte) ([]byte, error) {
	switch len(pubkey) {
	case 33:
		return pubkey[1:], nil
	case 32:
		return pubkey, nil
	default:
		return nil, &util.InvalidPointError{}
	}
}

// ConvertPubkeyToEcdsa converts a pubkey to ECDSA format (compressed, 33 bytes).
func ConvertPubkeyToEcdsa(pubkey []byte) ([]byte, error) {
	switch len(pubkey) {
	case 32:
		out := make([]byte, 33)
		out[0] = 0x02
		copy(out[1:], pubkey)
		return out, nil
	case 33:
		return pubkey, nil
	default:
		return nil, &util.InvalidPointError{}
	}
}
