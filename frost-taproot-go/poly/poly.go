// Package poly provides polynomial evaluation and Lagrange interpolation.
package poly

import (
	"fmt"
	"math/big"

	"github.com/frost-taproot/frost-taproot-go/ecc"
)

// EvaluateX evaluates a polynomial at x using Horner's method.
func EvaluateX(coeffs []*big.Int, x *big.Int) (*big.Int, error) {
	if x.Sign() == 0 {
		return nil, fmt.Errorf("x is zero")
	}

	value := big.NewInt(0)
	for i := len(coeffs) - 1; i >= 0; i-- {
		value = ecc.ModN(new(big.Int).Add(ecc.ScalarMul(value, x), coeffs[i]))
	}
	return value, nil
}

// InterpolateRoot interpolates at x=0 using Lagrange interpolation.
func InterpolateRoot(points [][2]*big.Int) (*big.Int, error) {
	xs := make([]*big.Int, len(points))
	for i, p := range points {
		xs[i] = p[0]
	}

	p := big.NewInt(0)
	for _, point := range points {
		x := point[0]
		y := point[1]
		delta, err := InterpolateX(xs, x)
		if err != nil {
			return nil, err
		}
		p = ecc.ScalarAdd(p, ecc.ScalarMul(delta, y))
	}
	return p, nil
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
	var b [32]byte
	b[28] = byte(idx >> 24)
	b[29] = byte(idx >> 16)
	b[30] = byte(idx >> 8)
	b[31] = byte(idx)
	return ecc.ScalarFromBytes(b)
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
