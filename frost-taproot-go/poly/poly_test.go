package poly

import (
	"math/big"
	"testing"

	"github.com/frost-taproot/frost-taproot-go/ecc"
)

// ── EvaluateX ────────────────────────────────────────────────────────────────

func TestEvaluateXConstantPolynomial(t *testing.T) {
	// f(x) = 7; f(3) == 7
	coeffs := []*big.Int{big.NewInt(7)}
	v, err := EvaluateX(coeffs, big.NewInt(3))
	if err != nil {
		t.Fatalf("EvaluateX failed: %v", err)
	}
	if v.Cmp(big.NewInt(7)) != 0 {
		t.Errorf("f(3) = %v, want 7", v)
	}
}

func TestEvaluateXLinear(t *testing.T) {
	// f(x) = 3 + 2x; f(1)=5, f(2)=7
	coeffs := []*big.Int{big.NewInt(3), big.NewInt(2)}
	v1, _ := EvaluateX(coeffs, big.NewInt(1))
	v2, _ := EvaluateX(coeffs, big.NewInt(2))
	if v1.Cmp(big.NewInt(5)) != 0 {
		t.Errorf("f(1) = %v, want 5", v1)
	}
	if v2.Cmp(big.NewInt(7)) != 0 {
		t.Errorf("f(2) = %v, want 7", v2)
	}
}

func TestEvaluateXAtZeroErrors(t *testing.T) {
	coeffs := []*big.Int{big.NewInt(5)}
	if _, err := EvaluateX(coeffs, big.NewInt(0)); err == nil {
		t.Error("EvaluateX at x=0 must return an error")
	}
}

func TestEvaluateXMatchesFixtureShare1(t *testing.T) {
	// fixture: secrets s0, s1; share[1] (x=1) should equal known hex
	s0, _ := new(big.Int).SetString("0070ca75929ca1ec4cd70ac34f46079bdfdd87f9d0c0bf4275f3882f7b462d0f", 16)
	s1, _ := new(big.Int).SetString("0e0376a7180253cdb8b6020bff0eda529760da65e715663e2152e4be2fc7b443", 16)
	coeffs := []*big.Int{ecc.ModN(s0), ecc.ModN(s1)}
	v, err := EvaluateX(coeffs, IndexToScalar(1))
	if err != nil {
		t.Fatalf("EvaluateX failed: %v", err)
	}
	want, _ := new(big.Int).SetString("0e74411caa9ef5ba058d0ccf4e54e1ee773e625fb7d6258097466cedab0de152", 16)
	if v.Cmp(ecc.ModN(want)) != 0 {
		t.Errorf("share[1] mismatch: got %x, want %x", v, want)
	}
}

// ── InterpolateRoot ───────────────────────────────────────────────────────────

func TestInterpolateRootRecoverySimple(t *testing.T) {
	// f(x) = 7 + 3x; f(1)=10, f(2)=13; root f(0)=7
	points := [][2]*big.Int{
		{big.NewInt(1), big.NewInt(10)},
		{big.NewInt(2), big.NewInt(13)},
	}
	root, err := InterpolateRoot(points)
	if err != nil {
		t.Fatalf("InterpolateRoot failed: %v", err)
	}
	if root.Cmp(big.NewInt(7)) != 0 {
		t.Errorf("root = %v, want 7", root)
	}
}

func TestInterpolateRootSinglePoint(t *testing.T) {
	// f(x) = c (constant); f(1)=5 → root = 5
	points := [][2]*big.Int{{big.NewInt(1), big.NewInt(5)}}
	root, err := InterpolateRoot(points)
	if err != nil {
		t.Fatalf("InterpolateRoot failed: %v", err)
	}
	if root.Cmp(big.NewInt(5)) != 0 {
		t.Errorf("root = %v, want 5", root)
	}
}

func TestInterpolateRootRecoveryFixtureSecret(t *testing.T) {
	// Using fixture shares at x=2 and x=3, interpolate to recover s0
	s0, _ := new(big.Int).SetString("0070ca75929ca1ec4cd70ac34f46079bdfdd87f9d0c0bf4275f3882f7b462d0f", 16)
	s1, _ := new(big.Int).SetString("0e0376a7180253cdb8b6020bff0eda529760da65e715663e2152e4be2fc7b443", 16)
	coeffs := []*big.Int{ecc.ModN(s0), ecc.ModN(s1)}
	share2, _ := EvaluateX(coeffs, IndexToScalar(2))
	share3, _ := EvaluateX(coeffs, IndexToScalar(3))
	points := [][2]*big.Int{
		{IndexToScalar(2), share2},
		{IndexToScalar(3), share3},
	}
	root, err := InterpolateRoot(points)
	if err != nil {
		t.Fatalf("InterpolateRoot failed: %v", err)
	}
	if root.Cmp(ecc.ModN(s0)) != 0 {
		t.Errorf("recovered secret mismatch")
	}
}

// ── InterpolateX ─────────────────────────────────────────────────────────────

func TestInterpolateXNotInSetErrors(t *testing.T) {
	l := []*big.Int{big.NewInt(1), big.NewInt(2)}
	if _, err := InterpolateX(l, big.NewInt(3)); err == nil {
		t.Error("InterpolateX with x not in set must error")
	}
}

func TestInterpolateXDuplicateErrors(t *testing.T) {
	l := []*big.Int{big.NewInt(1), big.NewInt(1)}
	if _, err := InterpolateX(l, big.NewInt(1)); err == nil {
		t.Error("InterpolateX with duplicate x values must error")
	}
}

func TestInterpolateXSingleElement(t *testing.T) {
	l := []*big.Int{big.NewInt(1)}
	v, err := InterpolateX(l, big.NewInt(1))
	if err != nil {
		t.Fatalf("InterpolateX single element failed: %v", err)
	}
	if v.Cmp(big.NewInt(1)) != 0 {
		t.Errorf("InterpolateX({1}, 1) = %v, want 1", v)
	}
}

// ── CalcLagrangeCoeff ─────────────────────────────────────────────────────────

func TestCalcLagrangeCoeffDuplicateErrors(t *testing.T) {
	l := []*big.Int{big.NewInt(1), big.NewInt(1)}
	if _, err := CalcLagrangeCoeff(l, big.NewInt(1), big.NewInt(0)); err == nil {
		t.Error("CalcLagrangeCoeff with duplicate L must error")
	}
}

func TestCalcLagrangeCoeffTwoPartyAtZero(t *testing.T) {
	// L={1,2}, P=1, x=0: λ = (0-2)/((1-2)) = (-2)/(-1) = 2
	l := []*big.Int{big.NewInt(1), big.NewInt(2)}
	v, err := CalcLagrangeCoeff(l, big.NewInt(1), big.NewInt(0))
	if err != nil {
		t.Fatalf("CalcLagrangeCoeff failed: %v", err)
	}
	if v.Cmp(big.NewInt(2)) != 0 {
		t.Errorf("CalcLagrangeCoeff = %v, want 2", v)
	}
}

// ── IndexToScalar ─────────────────────────────────────────────────────────────

func TestIndexToScalarOne(t *testing.T) {
	if IndexToScalar(1).Cmp(big.NewInt(1)) != 0 {
		t.Error("IndexToScalar(1) must be 1")
	}
}

func TestIndexToScalarZero(t *testing.T) {
	if IndexToScalar(0).Sign() != 0 {
		t.Error("IndexToScalar(0) must be 0")
	}
}

func TestIndexToScalarLarge(t *testing.T) {
	if IndexToScalar(255).Cmp(big.NewInt(255)) != 0 {
		t.Error("IndexToScalar(255) must be 255")
	}
}

// ── IsUniqueSet ───────────────────────────────────────────────────────────────

func TestIsUniqueSetDistinct(t *testing.T) {
	l := []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3)}
	if err := IsUniqueSet(l); err != nil {
		t.Errorf("IsUniqueSet of distinct values must pass: %v", err)
	}
}

func TestIsUniqueSetWithDuplicate(t *testing.T) {
	l := []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(1)}
	if err := IsUniqueSet(l); err == nil {
		t.Error("IsUniqueSet with duplicate must error")
	}
}

func TestIsUniqueSetZeroIsDistinct(t *testing.T) {
	// Zero must not collide with other zeros
	l := []*big.Int{big.NewInt(0), big.NewInt(0)}
	if err := IsUniqueSet(l); err == nil {
		t.Error("IsUniqueSet with two zeros must error")
	}
}
