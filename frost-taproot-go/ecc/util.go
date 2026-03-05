// Package ecc provides elliptic curve operations for secp256k1.
package ecc

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// secp256k1 curve parameters
var (
	// P is the field prime
	P, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
	// N is the group order
	N, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
)

// Point represents a point on the secp256k1 curve.
type Point struct {
	X, Y *big.Int
}

func toSecpPoint(p *Point) *secp256k1.JacobianPoint {
	if p == nil {
		return nil
	}
	var fX, fY, fZ secp256k1.FieldVal
	fX.SetByteSlice(p.X.Bytes())
	fY.SetByteSlice(p.Y.Bytes())
	fZ.SetInt(1)
	return &secp256k1.JacobianPoint{X: fX, Y: fY, Z: fZ}
}

func fromSecpPoint(p *secp256k1.JacobianPoint) *Point {
	if p == nil {
		return nil
	}
	aff := *p
	aff.ToAffine()
	return &Point{
		X: new(big.Int).SetBytes(aff.X.Bytes()[:]),
		Y: new(big.Int).SetBytes(aff.Y.Bytes()[:]),
	}
}

// PointOrNil is a pointer to Point that can be nil.
type PointOrNil *Point

// Scalar represents a scalar value mod N.
type Scalar = *big.Int

// ModN reduces a big.Int modulo N.
func ModN(x *big.Int) *big.Int {
	return new(big.Int).Mod(x, N)
}

// ScalarFromBytes creates a scalar from 32 bytes, reduced mod N.
func ScalarFromBytes(b [32]byte) *big.Int {
	return ModN(new(big.Int).SetBytes(b[:]))
}

// ScalarToBytes converts a scalar to 32 bytes.
func ScalarToBytes(s *big.Int) [32]byte {
	var out [32]byte
	t := new(big.Int).Mod(s, N)
	b := t.Bytes()
	copy(out[32-len(b):], b)
	return out
}

// ScalarAdd adds two scalars mod N.
func ScalarAdd(a, b *big.Int) *big.Int {
	return ModN(new(big.Int).Add(a, b))
}

// ScalarMul multiplies two scalars mod N.
func ScalarMul(a, b *big.Int) *big.Int {
	return ModN(new(big.Int).Mul(a, b))
}

// ScalarNeg negates a scalar mod N.
func ScalarNeg(a *big.Int) *big.Int {
	return ModN(new(big.Int).Neg(a))
}

// ScalarSub subtracts two scalars mod N.
func ScalarSub(a, b *big.Int) *big.Int {
	return ModN(new(big.Int).Sub(a, b))
}

// ScalarInvert computes the modular inverse of a scalar mod N.
func ScalarInvert(a *big.Int) (*big.Int, error) {
	if a.Sign() == 0 {
		return nil, fmt.Errorf("scalar inversion failed: zero scalar")
	}
	return new(big.Int).ModInverse(a, N), nil
}

// PowN computes base^exp mod N using repeated squaring.
func PowN(base, exp uint64) *big.Int {
	if exp == 0 {
		return big.NewInt(1)
	}
	result := big.NewInt(1)
	b := ModN(big.NewInt(int64(base)))
	e := exp
	for e > 0 {
		if e&1 == 1 {
			result = ScalarMul(result, b)
		}
		b = ScalarMul(b, b)
		e >>= 1
	}
	return result
}

// LiftX lifts an x-only or compressed pubkey to a Point.
func LiftX(bytes []byte) (*Point, error) {
	var xBytes []byte
	var wantOdd *bool
	switch len(bytes) {
	case 32:
		xBytes = bytes
	case 33:
		if bytes[0] != 0x02 && bytes[0] != 0x03 {
			return nil, fmt.Errorf("invalid point prefix")
		}
		odd := bytes[0] == 0x03
		wantOdd = &odd
		xBytes = bytes[1:]
	default:
		return nil, fmt.Errorf("invalid point encoding length: %d", len(bytes))
	}

	x := new(big.Int).SetBytes(xBytes)

	// y^2 = x^3 + 7 mod P
	x3 := new(big.Int).Exp(x, big.NewInt(3), P)
	y2 := new(big.Int).Add(x3, big.NewInt(7))
	y2.Mod(y2, P)

	// Compute square root mod P
	y := new(big.Int).ModSqrt(y2, P)
	if y == nil {
		return nil, fmt.Errorf("no square root for x")
	}

	if wantOdd != nil {
		if (y.Bit(0) == 1) != *wantOdd {
			y.Sub(P, y)
		}
	} else {
		// x-only input: use even Y
		if y.Bit(0) != 0 {
			y.Sub(P, y)
		}
	}

	return &Point{X: x, Y: y}, nil
}

// SerializePoint serializes a point to 33-byte compressed format.
func SerializePoint(p *Point) [33]byte {
	var out [33]byte
	if p.Y.Bit(0) == 0 {
		out[0] = 0x02
	} else {
		out[0] = 0x03
	}
	b := p.X.Bytes()
	copy(out[33-len(b):], b)
	return out
}

// DeserializePoint deserializes a 33-byte compressed point.
func DeserializePoint(b [33]byte) (*Point, error) {
	return LiftX(b[:])
}

// HasEvenY returns true if the point has an even Y coordinate.
func HasEvenY(p *Point) bool {
	return p.Y.Bit(0) == 0
}

// NegatePoint negates a point (flips Y).
func NegatePoint(p *Point) *Point {
	y := new(big.Int).Sub(P, p.Y)
	y.Mod(y, P)
	return &Point{
		X: new(big.Int).Set(p.X),
		Y: y,
	}
}

// ElementAdd adds two points. Either may be nil.
func ElementAdd(a, b PointOrNil) (*Point, error) {
	switch {
	case a == nil && b == nil:
		return nil, fmt.Errorf("both points are null")
	case a == nil:
		return b, nil
	case b == nil:
		return a, nil
	default:
		bNegY := new(big.Int).Sub(P, b.Y)
		bNegY.Mod(bNegY, P)
		if a.X.Cmp(b.X) == 0 && a.Y.Cmp(bNegY) == 0 {
			return nil, fmt.Errorf("point at infinity")
		}
		if a.X.Cmp(b.X) == 0 && a.Y.Cmp(b.Y) == 0 {
			return PointDouble(a), nil
		}
		return PointAdd(a, b), nil
	}
}

// PointAdd adds two distinct points.
func PointAdd(a, b *Point) *Point {
	ja := toSecpPoint(a)
	jb := toSecpPoint(b)
	var out secp256k1.JacobianPoint
	secp256k1.AddNonConst(ja, jb, &out)
	return fromSecpPoint(&out)
}

// PointDouble doubles a point.
func PointDouble(a *Point) *Point {
	ja := toSecpPoint(a)
	var out secp256k1.JacobianPoint
	secp256k1.DoubleNonConst(ja, &out)
	return fromSecpPoint(&out)
}

// ScalarBaseMulti computes k * G where G is the generator.
func ScalarBaseMulti(k *big.Int) *Point {
	var kb [32]byte
	kmod := ModN(k).Bytes()
	copy(kb[32-len(kmod):], kmod)
	var ks secp256k1.ModNScalar
	ks.SetBytes(&kb)
	var out secp256k1.JacobianPoint
	secp256k1.ScalarBaseMultNonConst(&ks, &out)
	return fromSecpPoint(&out)
}

// ScalarMulti computes k * P.
func ScalarMulti(p *Point, k *big.Int) *Point {
	jp := toSecpPoint(p)
	if jp == nil {
		return nil
	}
	var kb [32]byte
	kmod := ModN(k).Bytes()
	copy(kb[32-len(kmod):], kmod)
	var ks secp256k1.ModNScalar
	ks.SetBytes(&kb)
	var out secp256k1.JacobianPoint
	secp256k1.ScalarMultNonConst(&ks, jp, &out)
	return fromSecpPoint(&out)
}

// SerializeElement serializes a point.
func SerializeElement(p *Point) [33]byte {
	return SerializePoint(p)
}

// DeserializeElement deserializes a point.
func DeserializeElement(b [33]byte) (*Point, error) {
	return DeserializePoint(b)
}

// SerializeScalarU32 serializes a uint32 as 32-byte big-endian.
func SerializeScalarU32(idx uint32) [32]byte {
	var out [32]byte
	b := make([]byte, 4)
	b[0] = byte(idx >> 24)
	b[1] = byte(idx >> 16)
	b[2] = byte(idx >> 8)
	b[3] = byte(idx)
	copy(out[28:], b)
	return out
}

// RandomBytes generates random bytes.
func RandomBytes(size int) []byte {
	buf := make([]byte, size)
	rand.Read(buf)
	return buf
}

// RandomBytes32 generates 32 random bytes.
func RandomBytes32() [32]byte {
	var buf [32]byte
	rand.Read(buf[:])
	return buf
}

// Gx, Gy are the generator point coordinates
var (
	Gx, _ = new(big.Int).SetString("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16)
	Gy, _ = new(big.Int).SetString("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
)
