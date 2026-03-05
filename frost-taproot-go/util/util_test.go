package util

import (
	"testing"
)

// ── OK ────────────────────────────────────────────────────────────────────────

func TestOKPassesForTrue(t *testing.T) {
	if err := OK(true, "should not fail"); err != nil {
		t.Errorf("OK(true) must return nil, got %v", err)
	}
}

func TestOKFailsForFalse(t *testing.T) {
	err := OK(false, "expected failure")
	if err == nil {
		t.Error("OK(false) must return an error")
	}
	if err.Error() != "assertion failed: expected failure" {
		t.Errorf("unexpected error message: %q", err.Error())
	}
}

// ── IsIncluded ────────────────────────────────────────────────────────────────

func TestIsIncludedFindsItem(t *testing.T) {
	if err := IsIncluded([]int{1, 2, 3}, 2); err != nil {
		t.Errorf("IsIncluded must find 2 in [1,2,3]: %v", err)
	}
}

func TestIsIncludedMissingItem(t *testing.T) {
	if err := IsIncluded([]int{1, 2, 3}, 4); err == nil {
		t.Error("IsIncluded must error when item is absent")
	}
}

func TestIsIncludedEmptySlice(t *testing.T) {
	if err := IsIncluded([]string{}, "x"); err == nil {
		t.Error("IsIncluded on empty slice must error")
	}
}

// ── IsUniqueSet ───────────────────────────────────────────────────────────────

func TestIsUniqueSetAllDistinct(t *testing.T) {
	if err := IsUniqueSet([]int{1, 2, 3}); err != nil {
		t.Errorf("IsUniqueSet of distinct values must pass: %v", err)
	}
}

func TestIsUniqueSetWithDuplicate(t *testing.T) {
	if err := IsUniqueSet([]int{1, 2, 2}); err == nil {
		t.Error("IsUniqueSet with duplicate must error")
	}
}

func TestIsUniqueSetEmpty(t *testing.T) {
	if err := IsUniqueSet([]int{}); err != nil {
		t.Errorf("IsUniqueSet of empty slice must pass: %v", err)
	}
}

// ── IsEqualSet ────────────────────────────────────────────────────────────────

func TestIsEqualSetAllEqual(t *testing.T) {
	if err := IsEqualSet([]int{5, 5, 5}); err != nil {
		t.Errorf("IsEqualSet of equal items must pass: %v", err)
	}
}

func TestIsEqualSetNotEqual(t *testing.T) {
	if err := IsEqualSet([]int{5, 5, 6}); err == nil {
		t.Error("IsEqualSet with differing items must error")
	}
}

func TestIsEqualSetSingleItem(t *testing.T) {
	if err := IsEqualSet([]int{42}); err != nil {
		t.Errorf("IsEqualSet of single item must pass: %v", err)
	}
}

func TestIsEqualSetEmpty(t *testing.T) {
	if err := IsEqualSet([]int{}); err != nil {
		t.Errorf("IsEqualSet of empty slice must pass: %v", err)
	}
}

// ── EqualArrSize ──────────────────────────────────────────────────────────────

func TestEqualArrSizeSameLength(t *testing.T) {
	if err := EqualArrSize([]int{1, 2}, []string{"a", "b"}); err != nil {
		t.Errorf("EqualArrSize of same-length arrays must pass: %v", err)
	}
}

func TestEqualArrSizeDifferentLength(t *testing.T) {
	if err := EqualArrSize([]int{1, 2}, []string{"a"}); err == nil {
		t.Error("EqualArrSize of different lengths must error")
	}
}

// ── HexToBytes / HexTo32 / HexTo33 / BytesToHex ──────────────────────────────

func TestHexToBytesRoundtrip(t *testing.T) {
	original := []byte{0xde, 0xad, 0xbe, 0xef}
	hex := BytesToHex(original)
	if hex != "deadbeef" {
		t.Errorf("BytesToHex: got %q, want %q", hex, "deadbeef")
	}
	back, err := HexToBytes(hex)
	if err != nil {
		t.Fatalf("HexToBytes failed: %v", err)
	}
	for i, b := range back {
		if b != original[i] {
			t.Errorf("roundtrip byte %d: got %x, want %x", i, b, original[i])
		}
	}
}

func TestHexToBytesInvalidLengthErrors(t *testing.T) {
	if _, err := HexToBytes("abc"); err == nil {
		t.Error("HexToBytes of odd-length string must error")
	}
}

func TestHexToBytesInvalidCharsErrors(t *testing.T) {
	if _, err := HexToBytes("zz"); err == nil {
		t.Error("HexToBytes of non-hex chars must error")
	}
}

func TestHexTo32ValidHex(t *testing.T) {
	hex := "0e74411caa9ef5ba058d0ccf4e54e1ee773e625fb7d6258097466cedab0de152"
	b, err := HexTo32(hex)
	if err != nil {
		t.Fatalf("HexTo32 failed: %v", err)
	}
	if b[0] != 0x0e {
		t.Errorf("first byte: got %x, want 0e", b[0])
	}
}

func TestHexTo32WrongLengthErrors(t *testing.T) {
	if _, err := HexTo32("deadbeef"); err == nil {
		t.Error("HexTo32 of 4-byte hex must error")
	}
}

func TestHexTo33ValidHex(t *testing.T) {
	hex := "021ae63bc9ddaffe52d44c3018e83115bfb22195bd8112fcad112310714e6fd5ec"
	b, err := HexTo33(hex)
	if err != nil {
		t.Fatalf("HexTo33 failed: %v", err)
	}
	if b[0] != 0x02 {
		t.Errorf("prefix byte: got %x, want 02", b[0])
	}
}

func TestHexTo33WrongLengthErrors(t *testing.T) {
	if _, err := HexTo33("deadbeef"); err == nil {
		t.Error("HexTo33 of 4-byte hex must error")
	}
}

// ── GetRecord ─────────────────────────────────────────────────────────────────

type testRecord struct{ id uint32 }

func (r testRecord) GetID() uint32 { return r.id }

func TestGetRecordFindsItem(t *testing.T) {
	records := []testRecord{{1}, {2}, {3}}
	r, err := GetRecord(records, 2)
	if err != nil {
		t.Fatalf("GetRecord failed: %v", err)
	}
	if r.id != 2 {
		t.Errorf("GetRecord returned wrong item: %d", r.id)
	}
}

func TestGetRecordNotFoundErrors(t *testing.T) {
	records := []testRecord{{1}, {2}}
	if _, err := GetRecord(records, 5); err == nil {
		t.Error("GetRecord must error when item is absent")
	}
}
