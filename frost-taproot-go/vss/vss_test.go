package vss

import (
	"math/big"
	"testing"

	"github.com/frost-taproot/frost-taproot-go/ecc"
)

func s32(hex string) [32]byte {
	b := make([]byte, len(hex)/2)
	for i := range b {
		hi := nibble(hex[i*2])
		lo := nibble(hex[i*2+1])
		b[i] = hi<<4 | lo
	}
	var out [32]byte
	copy(out[:], b)
	return out
}

func nibble(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	}
	return 0
}

func toHex(b []byte) string {
	const chars = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = chars[v>>4]
		out[i*2+1] = chars[v&0xf]
	}
	return string(out)
}

const (
	s0hex = "0070ca75929ca1ec4cd70ac34f46079bdfdd87f9d0c0bf4275f3882f7b462d0f"
	s1hex = "0e0376a7180253cdb8b6020bff0eda529760da65e715663e2152e4be2fc7b443"
)

// ── CreateShareCoeffs ────────────────────────────────────────────────────────

func TestCreateShareCoeffsUsesProvidedSecrets(t *testing.T) {
	s0 := s32(s0hex)
	s1 := s32(s1hex)
	coeffs := CreateShareCoeffs([][32]byte{s0, s1}, 2)
	if len(coeffs) != 2 {
		t.Fatalf("expected 2 coeffs, got %d", len(coeffs))
	}
	want0 := ecc.ScalarFromBytes(s0)
	want1 := ecc.ScalarFromBytes(s1)
	if coeffs[0].Cmp(want0) != 0 {
		t.Error("coeffs[0] must equal s0")
	}
	if coeffs[1].Cmp(want1) != 0 {
		t.Error("coeffs[1] must equal s1")
	}
}

func TestCreateShareCoeffsFillsRandomWhenShort(t *testing.T) {
	s0 := s32(s0hex)
	coeffs := CreateShareCoeffs([][32]byte{s0}, 3)
	if len(coeffs) != 3 {
		t.Fatalf("expected 3 coeffs, got %d", len(coeffs))
	}
	want := ecc.ScalarFromBytes(s0)
	if coeffs[0].Cmp(want) != 0 {
		t.Error("first coeff must equal s0")
	}
	// Random coefficients should be non-zero with overwhelming probability
	if coeffs[1].Sign() == 0 {
		t.Error("random coeff[1] must be non-zero")
	}
}

func TestCreateShareCoeffsEmptySecretsAllRandom(t *testing.T) {
	coeffs := CreateShareCoeffs(nil, 3)
	if len(coeffs) != 3 {
		t.Fatalf("expected 3 coeffs, got %d", len(coeffs))
	}
}

func TestCreateShareCoeffsThresholdZeroIsEmpty(t *testing.T) {
	coeffs := CreateShareCoeffs(nil, 0)
	if len(coeffs) != 0 {
		t.Errorf("threshold 0 must produce empty coeffs, got %d", len(coeffs))
	}
}

func TestCreateShareCoeffsTwoDifferentCallsProduceDifferentRandoms(t *testing.T) {
	a := CreateShareCoeffs(nil, 2)
	b := CreateShareCoeffs(nil, 2)
	// Extremely unlikely to be equal
	if a[0].Cmp(b[0]) == 0 && a[1].Cmp(b[1]) == 0 {
		t.Error("two random coefficient sets must differ")
	}
}

// ── GetShareCommits ───────────────────────────────────────────────────────────

func TestGetShareCommitsMatchesFixture(t *testing.T) {
	s0 := s32(s0hex)
	s1 := s32(s1hex)
	coeffs := CreateShareCoeffs([][32]byte{s0, s1}, 2)
	commits := GetShareCommits(coeffs)
	if len(commits) != 2 {
		t.Fatalf("expected 2 commits, got %d", len(commits))
	}
	want0 := "021ae63bc9ddaffe52d44c3018e83115bfb22195bd8112fcad112310714e6fd5ec"
	want1 := "024f75a5478deda1102eba931e19425e59c1750533a54218ce215ced343fbfb6cf"
	if toHex(commits[0][:]) != want0 {
		t.Errorf("commit[0] mismatch:\n  got  %s\n  want %s", toHex(commits[0][:]), want0)
	}
	if toHex(commits[1][:]) != want1 {
		t.Errorf("commit[1] mismatch:\n  got  %s\n  want %s", toHex(commits[1][:]), want1)
	}
}

func TestGetShareCommitsCommitIsScalarTimesGenerator(t *testing.T) {
	s0 := s32(s0hex)
	coeffs := CreateShareCoeffs([][32]byte{s0}, 1)
	commits := GetShareCommits(coeffs)
	expected := ecc.SerializePoint(ecc.ScalarBaseMulti(coeffs[0]))
	if commits[0] != expected {
		t.Error("commit must equal coeff * G")
	}
}

// ── MergeShareCommits ────────────────────────────────────────────────────────

func TestMergeShareCommitsAddsPoints(t *testing.T) {
	s0 := s32(s0hex)
	s1 := s32(s1hex)
	coeffsA := CreateShareCoeffs([][32]byte{s0}, 1)
	coeffsB := CreateShareCoeffs([][32]byte{s1}, 1)
	commitsA := GetShareCommits(coeffsA)
	commitsB := GetShareCommits(coeffsB)
	merged, err := MergeShareCommits(commitsA, commitsB)
	if err != nil {
		t.Fatalf("MergeShareCommits failed: %v", err)
	}
	// merged[0] = (s0 + s1) * G
	combined := new(big.Int).Add(coeffsA[0], coeffsB[0])
	expected := ecc.SerializePoint(ecc.ScalarBaseMulti(ecc.ModN(combined)))
	if merged[0] != expected {
		t.Error("merged commit must equal (a + b) * G")
	}
}

func TestMergeShareCommitsMismatchedLengthsErrors(t *testing.T) {
	s0 := s32(s0hex)
	coeffsA := CreateShareCoeffs([][32]byte{s0}, 1)
	commitsA := GetShareCommits(coeffsA)
	if _, err := MergeShareCommits(commitsA, nil); err == nil {
		t.Error("MergeShareCommits with mismatched lengths must error")
	}
}
