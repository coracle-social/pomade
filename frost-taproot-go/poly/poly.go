// Package poly provides polynomial evaluation and Lagrange interpolation.
package poly

import (
	"fmt"
	"math/big"

	"github.com/frost-taproot/frost-taproot-go/ecc"
)

// EvaluateX evaluates a polynomial at x using Horner's method. The coefficients
// are secret-bearing (secret shares / poly coefficients) while x is a public
// participant index, so the per-step multiply and add run in constant time wrt
// the secret accumulator (see ecc.ScalarMulCT / ecc.ScalarAddCT).
func EvaluateX(coeffs []*big.Int, x *big.Int) (*big.Int, error) {
	if x.Sign() == 0 {
		return nil, fmt.Errorf("x is zero")
	}
	if len(coeffs) == 0 {
		return big.NewInt(0), nil
	}

	xb := ecc.ScalarToBytes(x)
	value := ecc.ScalarToBytes(coeffs[len(coeffs)-1])
	for i := len(coeffs) - 2; i >= 0; i-- {
		value = ecc.ScalarAddCT(ecc.ScalarMulCT(value, xb), ecc.ScalarToBytes(coeffs[i]))
	}
	return ecc.ScalarFromBytes(value), nil
}

// InterpolateRoot interpolates at x=0 using Lagrange interpolation.
func InterpolateRoot(points [][2]*big.Int) (*big.Int, error) {
	xs := make([]*big.Int, len(points))
	for i, p := range points {
		xs[i] = p[0]
	}

	// delta is a public Lagrange basis value over public indices, but y is a
	// secret share, so the multiply and the running sum keep a secret as base and
	// run in constant time wrt the secret (see ecc.ScalarMulCT / ecc.ScalarAddCT).
	var p [32]byte
	first := true
	for _, point := range points {
		x := point[0]
		y := point[1]
		delta, err := InterpolateX(xs, x)
		if err != nil {
			return nil, err
		}
		term := ecc.ScalarMulCT(ecc.ScalarToBytes(y), ecc.ScalarToBytes(delta))
		if first {
			p = term
			first = false
		} else {
			p = ecc.ScalarAddCT(p, term)
		}
	}
	return ecc.ScalarFromBytes(p), nil
}

// InterpolateX computes Lagrange basis at x=0.
func InterpolateX(l []*big.Int, x *big.Int) (*big.Int, error) {
	if !isIncluded(l, x) {
		return nil, fmt.Errorf("x not included in set")
	}
	if err := IsUniqueSet(l); err != nil {
		return nil, err
	}

	numerator := big.NewInt(1)
	denominator := big.NewInt(1)

	for _, xj := range l {
		if xj.Cmp(x) == 0 {
			continue
		}
		numerator = ecc.ScalarMul(numerator, xj)
		denominator = ecc.ScalarMul(denominator, ecc.ScalarAdd(xj, ecc.ScalarNeg(x)))
	}

	inv, err := ecc.ScalarInvert(denominator)
	if err != nil {
		return nil, err
	}
	return ecc.ScalarMul(numerator, inv), nil
}

// CalcLagrangeCoeff computes Lagrange coefficient.
func CalcLagrangeCoeff(l []*big.Int, p, x *big.Int) (*big.Int, error) {
	if err := IsUniqueSet(l); err != nil {
		return nil, err
	}

	numerator := big.NewInt(1)
	denominator := big.NewInt(1)

	for _, xj := range l {
		if xj.Cmp(p) == 0 {
			continue
		}
		numerator = ecc.ScalarMul(numerator, ecc.ScalarAdd(x, ecc.ScalarNeg(xj)))
		denominator = ecc.ScalarMul(denominator, ecc.ScalarAdd(p, ecc.ScalarNeg(xj)))
	}

	inv, err := ecc.ScalarInvert(denominator)
	if err != nil {
		return nil, err
	}
	return ecc.ScalarMul(numerator, inv), nil
}

// IndexToScalar converts uint32 to scalar.
func IndexToScalar(idx uint32) *big.Int {
	return ecc.ScalarFromBytes(ecc.SerializeScalarU32(idx))
}

// IsUniqueSet checks if all elements are unique.
func IsUniqueSet(l []*big.Int) error {
	seen := make(map[string]bool)
	for _, x := range l {
		key := x.Text(16)
		if seen[key] {
			return fmt.Errorf("duplicate element in set")
		}
		seen[key] = true
	}
	return nil
}

func isIncluded(l []*big.Int, x *big.Int) bool {
	for _, v := range l {
		if v.Cmp(x) == 0 {
			return true
		}
	}
	return false
}
