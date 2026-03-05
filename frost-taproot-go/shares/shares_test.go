package shares

import (
	"testing"

	"github.com/frost-taproot/frost-taproot-go/ecc"
	"github.com/frost-taproot/frost-taproot-go/types"
	"github.com/frost-taproot/frost-taproot-go/vss"
)

func s32(hex string) [32]byte {
	b := decodeHex(hex)
	var out [32]byte
	copy(out[:], b)
	return out
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

func decodeHex(s string) []byte {
	b := make([]byte, len(s)/2)
	for i := range b {
		b[i] = nibble(s[i*2])<<4 | nibble(s[i*2+1])
	}
	return b
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

func share(id uint32, hex string) types.SecretShare {
	return types.SecretShare{ID: id, Seckey: s32(hex)}
}

const (
	s0hex = "0070ca75929ca1ec4cd70ac34f46079bdfdd87f9d0c0bf4275f3882f7b462d0f"
	s1hex = "0e0376a7180253cdb8b6020bff0eda529760da65e715663e2152e4be2fc7b443"
)

// ── CreateShares ──────────────────────────────────────────────────────────────

func TestCreateSharesCountAndIndices(t *testing.T) {
	coeffs := vss.CreateShareCoeffs([][32]byte{s32(s0hex), s32(s1hex)}, 2)
	shares, err := CreateShares(coeffs, 3)
	if err != nil {
		t.Fatalf("CreateShares failed: %v", err)
	}
	if len(shares) != 3 {
		t.Fatalf("expected 3 shares, got %d", len(shares))
	}
	for i, s := range shares {
		if s.ID != uint32(i+1) {
			t.Errorf("share[%d].ID = %d, want %d", i, s.ID, i+1)
		}
	}
}

func TestCreateSharesMatchesFixture(t *testing.T) {
	coeffs := vss.CreateShareCoeffs([][32]byte{s32(s0hex), s32(s1hex)}, 2)
	shares, err := CreateShares(coeffs, 3)
	if err != nil {
		t.Fatalf("CreateShares failed: %v", err)
	}
	want := []string{
		"0e74411caa9ef5ba058d0ccf4e54e1ee773e625fb7d6258097466cedab0de152",
		"1c77b7c3c2a14987be430edb4d63bc410e9f3cc59eeb8bbeb89951abdad59595",
		"2a7b2e6adaa39d5576f910e74c729693a600172b8600f1fcd9ec366a0a9d49d8",
	}
	for i, s := range shares {
		if toHex(s.Seckey[:]) != want[i] {
			t.Errorf("share[%d] seckey mismatch:\n  got  %s\n  want %s", i, toHex(s.Seckey[:]), want[i])
		}
	}
}

// ── CombineShares ─────────────────────────────────────────────────────────────

func TestCombineSharesSumsScalars(t *testing.T) {
	a := share(1, "0000000000000000000000000000000000000000000000000000000000000003")
	b := share(2, "0000000000000000000000000000000000000000000000000000000000000004")
	result := CombineShares([]types.SecretShare{a, b})
	expected := ecc.ScalarToBytes(ecc.ScalarFromBytes([32]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7}))
	if result != expected {
		t.Errorf("CombineShares(3+4) = %x, want 7", result)
	}
}

func TestCombineSharesSingleShare(t *testing.T) {
	a := share(1, "0e74411caa9ef5ba058d0ccf4e54e1ee773e625fb7d6258097466cedab0de152")
	result := CombineShares([]types.SecretShare{a})
	if result != a.Seckey {
		t.Error("CombineShares of single share must return that share's seckey")
	}
}

// ── CombineSet ────────────────────────────────────────────────────────────────

func TestCombineSetSameID(t *testing.T) {
	a := share(1, "0000000000000000000000000000000000000000000000000000000000000003")
	b := share(1, "0000000000000000000000000000000000000000000000000000000000000004")
	result, err := CombineSet([]types.SecretShare{a, b})
	if err != nil {
		t.Fatalf("CombineSet failed: %v", err)
	}
	if result.ID != 1 {
		t.Errorf("CombineSet ID = %d, want 1", result.ID)
	}
	if result.Seckey[31] != 7 {
		t.Errorf("CombineSet seckey last byte = %d, want 7", result.Seckey[31])
	}
}

func TestCombineSetMismatchedIDErrors(t *testing.T) {
	a := share(1, "0000000000000000000000000000000000000000000000000000000000000003")
	b := share(2, "0000000000000000000000000000000000000000000000000000000000000004")
	if _, err := CombineSet([]types.SecretShare{a, b}); err == nil {
		t.Error("CombineSet with mismatched IDs must error")
	}
}

// ── MergeShares ───────────────────────────────────────────────────────────────

func TestMergeSharesCombinesMatchingIndices(t *testing.T) {
	a1 := share(1, "0000000000000000000000000000000000000000000000000000000000000003")
	a2 := share(2, "0000000000000000000000000000000000000000000000000000000000000005")
	b1 := share(1, "0000000000000000000000000000000000000000000000000000000000000004")
	b2 := share(2, "0000000000000000000000000000000000000000000000000000000000000006")
	merged, err := MergeShares([]types.SecretShare{a1, a2}, []types.SecretShare{b1, b2})
	if err != nil {
		t.Fatalf("MergeShares failed: %v", err)
	}
	if merged[0].ID != 1 || merged[0].Seckey[31] != 7 {
		t.Errorf("merged[0]: ID=%d, last byte=%d; want ID=1, last byte=7", merged[0].ID, merged[0].Seckey[31])
	}
	if merged[1].ID != 2 || merged[1].Seckey[31] != 11 {
		t.Errorf("merged[1]: ID=%d, last byte=%d; want ID=2, last byte=11", merged[1].ID, merged[1].Seckey[31])
	}
}

func TestMergeSharesMismatchedLengthsErrors(t *testing.T) {
	a := []types.SecretShare{share(1, "0000000000000000000000000000000000000000000000000000000000000001")}
	if _, err := MergeShares(a, nil); err == nil {
		t.Error("MergeShares with different lengths must error")
	}
}

func TestMergeSharesMissingIDErrors(t *testing.T) {
	a := []types.SecretShare{share(1, "0000000000000000000000000000000000000000000000000000000000000001")}
	b := []types.SecretShare{share(9, "0000000000000000000000000000000000000000000000000000000000000002")} // ID mismatch
	if _, err := MergeShares(a, b); err == nil {
		t.Error("MergeShares where IDs don't match must error")
	}
}

// ── DeriveSharesSecret ────────────────────────────────────────────────────────

func TestDeriveSharesSecretRecoversRoot(t *testing.T) {
	coeffs := vss.CreateShareCoeffs([][32]byte{s32(s0hex), s32(s1hex)}, 2)
	allShares, _ := CreateShares(coeffs, 3)
	// Any 2-of-3 subset must recover s0
	subsets := [][2]int{{0, 1}, {0, 2}, {1, 2}}
	for _, ss := range subsets {
		secret, err := DeriveSharesSecret([]types.SecretShare{allShares[ss[0]], allShares[ss[1]]})
		if err != nil {
			t.Fatalf("DeriveSharesSecret failed: %v", err)
		}
		if toHex(secret[:]) != s0hex {
			t.Errorf("subset %v: recovered secret mismatch:\n  got  %s\n  want %s", ss, toHex(secret[:]), s0hex)
		}
	}
}

// ── VerifyShare ───────────────────────────────────────────────────────────────

func TestVerifyShareValidShares(t *testing.T) {
	coeffs := vss.CreateShareCoeffs([][32]byte{s32(s0hex), s32(s1hex)}, 2)
	allShares, _ := CreateShares(coeffs, 3)
	commits := vss.GetShareCommits(coeffs)
	for _, s := range allShares {
		ok, err := VerifyShare(commits, &s, 2)
		if err != nil {
			t.Fatalf("VerifyShare error for idx %d: %v", s.ID, err)
		}
		if !ok {
			t.Errorf("share %d should be valid", s.ID)
		}
	}
}

func TestVerifyShareTamperedFails(t *testing.T) {
	coeffs := vss.CreateShareCoeffs([][32]byte{s32(s0hex), s32(s1hex)}, 2)
	allShares, _ := CreateShares(coeffs, 3)
	commits := vss.GetShareCommits(coeffs)
	tampered := allShares[0]
	tampered.Seckey[0] ^= 0xff
	ok, err := VerifyShare(commits, &tampered, 2)
	if err != nil {
		t.Fatalf("VerifyShare error: %v", err)
	}
	if ok {
		t.Error("tampered share must fail verification")
	}
}

func TestVerifyShareZeroThresholdErrors(t *testing.T) {
	s := share(1, "0e74411caa9ef5ba058d0ccf4e54e1ee773e625fb7d6258097466cedab0de152")
	if _, err := VerifyShare(nil, &s, 0); err == nil {
		t.Error("VerifyShare with threshold 0 must error")
	}
}
