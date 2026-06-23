package ecc

import (
	"crypto/rand"
	"math/big"
	"testing"
)

// randScalarBytes returns a uniformly random canonical scalar in [1, N-1].
func randScalarBytes(t *testing.T) [32]byte {
	t.Helper()
	for {
		var b [32]byte
		if _, err := rand.Read(b[:]); err != nil {
			t.Fatalf("rand: %v", err)
		}
		s := ScalarFromBytes(b)
		if s.Sign() == 0 {
			continue
		}
		return ScalarToBytes(s)
	}
}

// The constant-time base multiply must equal the decred path for valid scalars,
// and the constant-time path (not the fallback) must actually be taken.
func TestScalarBaseMultiCTMatchesDecred(t *testing.T) {
	for i := 0; i < 64; i++ {
		k := randScalarBytes(t)
		ct, ok := scalarBaseMultCT(k)
		if !ok {
			t.Fatalf("scalarBaseMultCT rejected a valid scalar %x", k)
		}
		want := SerializePoint(ScalarBaseMulti(ScalarFromBytes(k)))
		if ct != want {
			t.Fatalf("base mult mismatch:\n  ct   %x\n  want %x", ct, want)
		}
		if ScalarBaseMultiCT(k) != want {
			t.Fatalf("ScalarBaseMultiCT wrapper mismatch")
		}
	}
}

// The constant-time variable-base multiply (used by ECDH) must equal the decred
// path for valid points and scalars.
func TestScalarMultiCTMatchesDecred(t *testing.T) {
	for i := 0; i < 64; i++ {
		P := ScalarBaseMulti(ScalarFromBytes(randScalarBytes(t)))
		pc := SerializePoint(P)
		k := randScalarBytes(t)
		ct, ok := pointScalarMultCT(pc, k)
		if !ok {
			t.Fatalf("pointScalarMultCT rejected valid inputs")
		}
		want := SerializePoint(ScalarMulti(P, ScalarFromBytes(k)))
		if ct != want {
			t.Fatalf("point mult mismatch:\n  ct   %x\n  want %x", ct, want)
		}
		if ScalarMultiCT(pc, k) != want {
			t.Fatalf("ScalarMultiCT wrapper mismatch")
		}
	}
}

func TestScalarMulCTMatchesBig(t *testing.T) {
	for i := 0; i < 128; i++ {
		a := randScalarBytes(t)
		b := randScalarBytes(t)
		ct, ok := seckeyTweakMulCT(a, b)
		if !ok {
			t.Fatalf("seckeyTweakMulCT rejected valid scalars")
		}
		want := ScalarToBytes(ScalarMul(ScalarFromBytes(a), ScalarFromBytes(b)))
		if ct != want || ScalarMulCT(a, b) != want {
			t.Fatalf("scalar mul mismatch:\n  ct   %x\n  want %x", ct, want)
		}
	}
}

func TestScalarAddCTMatchesBig(t *testing.T) {
	for i := 0; i < 128; i++ {
		a := randScalarBytes(t)
		b := randScalarBytes(t)
		ct, ok := seckeyTweakAddCT(a, b)
		if !ok {
			continue // sum is zero (a == -b); negligible, skip
		}
		want := ScalarToBytes(ScalarAdd(ScalarFromBytes(a), ScalarFromBytes(b)))
		if ct != want || ScalarAddCT(a, b) != want {
			t.Fatalf("scalar add mismatch:\n  ct   %x\n  want %x", ct, want)
		}
	}
}

func TestScalarNegCTMatchesBig(t *testing.T) {
	for i := 0; i < 64; i++ {
		a := randScalarBytes(t)
		ct, ok := seckeyNegateCT(a)
		if !ok {
			t.Fatalf("seckeyNegateCT rejected valid scalar")
		}
		want := ScalarToBytes(ScalarNeg(ScalarFromBytes(a)))
		if ct != want || ScalarNegCT(a) != want {
			t.Fatalf("scalar neg mismatch")
		}
		if ScalarAdd(ScalarFromBytes(a), ScalarFromBytes(ct)).Sign() != 0 {
			t.Fatalf("a + neg(a) must be 0")
		}
	}
}

// The constant-time Fermat inverse must equal the big.Int ModInverse, and
// x * inv(x) must be 1 for several random scalars.
func TestScalarInvertCTMatchesBig(t *testing.T) {
	for i := 0; i < 128; i++ {
		x := randScalarBytes(t)

		ct, err := ScalarInvertCT(x)
		if err != nil {
			t.Fatalf("ScalarInvertCT rejected valid scalar %x: %v", x, err)
		}

		want, err := ScalarInvert(ScalarFromBytes(x))
		if err != nil {
			t.Fatalf("ScalarInvert failed for %x: %v", x, err)
		}
		if ct != ScalarToBytes(want) {
			t.Fatalf("inverse mismatch for %x:\n  ct   %x\n  want %x", x, ct, ScalarToBytes(want))
		}

		if prod := ScalarMul(ScalarFromBytes(x), ScalarFromBytes(ct)); prod.Cmp(big.NewInt(1)) != 0 {
			t.Fatalf("x * inv(x) must be 1, got %x", ScalarToBytes(prod))
		}
	}
}

// A zero scalar has no inverse and must be rejected.
func TestScalarInvertCTZero(t *testing.T) {
	var zero [32]byte
	if _, err := ScalarInvertCT(zero); err == nil {
		t.Fatalf("ScalarInvertCT(0) must return an error")
	}
}

// Degenerate inputs (which never arise from real secrets) must fall back to the
// pure-Go path and still produce the correct result.
func TestScalarMulCTZeroFallback(t *testing.T) {
	a := randScalarBytes(t)
	var zero [32]byte
	if _, ok := seckeyTweakMulCT(a, zero); ok {
		t.Fatalf("seckeyTweakMulCT must reject a zero tweak")
	}
	if ScalarMulCT(a, zero) != [32]byte{} {
		t.Fatalf("ScalarMulCT(a, 0) must be 0 via fallback")
	}
}
