package ecc

import (
	"math/big"
	"testing"
)

// ── Scalar arithmetic ─────────────────────────────────────────────────────────

func TestModNZeroIsZero(t *testing.T) {
	if ModN(big.NewInt(0)).Sign() != 0 {
		t.Error("ModN(0) must be zero")
	}
}

func TestModNOneIsOne(t *testing.T) {
	if ModN(big.NewInt(1)).Cmp(big.NewInt(1)) != 0 {
		t.Error("ModN(1) must be 1")
	}
}

func TestModNReducesNToZero(t *testing.T) {
	if ModN(new(big.Int).Set(N)).Sign() != 0 {
		t.Error("ModN(N) must be 0")
	}
}

func TestModNReducesNPlusOneToOne(t *testing.T) {
	nPlusOne := new(big.Int).Add(N, big.NewInt(1))
	if ModN(nPlusOne).Cmp(big.NewInt(1)) != 0 {
		t.Error("ModN(N+1) must be 1")
	}
}

func TestScalarRoundtrip(t *testing.T) {
	var b [32]byte
	b[31] = 42
	s := ScalarFromBytes(b)
	out := ScalarToBytes(s)
	if out != b {
		t.Errorf("scalar roundtrip failed: got %x, want %x", out, b)
	}
}

func TestScalarFromZeroBytesIsZero(t *testing.T) {
	s := ScalarFromBytes([32]byte{})
	if s.Sign() != 0 {
		t.Error("ScalarFromBytes(zeros) must be zero")
	}
}

func TestScalarAddModN(t *testing.T) {
	// N-1 + 1 = 0 mod N
	nMinus1 := new(big.Int).Sub(N, big.NewInt(1))
	var b [32]byte
	copy(b[:], nMinus1.Bytes())
	a := ScalarFromBytes(b)
	one := big.NewInt(1)
	result := ScalarAdd(a, one)
	if result.Sign() != 0 {
		t.Errorf("(N-1)+1 mod N must be 0, got %x", result)
	}
}

func TestScalarNeg(t *testing.T) {
	one := big.NewInt(1)
	neg := ScalarNeg(one)
	sum := ScalarAdd(one, neg)
	if sum.Sign() != 0 {
		t.Errorf("1 + ScalarNeg(1) must be 0, got %x", sum)
	}
}

func TestScalarSub(t *testing.T) {
	a := big.NewInt(5)
	b := big.NewInt(3)
	if ScalarSub(a, b).Cmp(big.NewInt(2)) != 0 {
		t.Error("5 - 3 must be 2")
	}
}

func TestScalarMul(t *testing.T) {
	a := big.NewInt(7)
	b := big.NewInt(11)
	if ScalarMul(a, b).Cmp(big.NewInt(77)) != 0 {
		t.Error("7 * 11 must be 77")
	}
}

func TestScalarInvertRoundtrip(t *testing.T) {
	a := big.NewInt(7)
	inv, err := ScalarInvert(a)
	if err != nil {
		t.Fatalf("ScalarInvert failed: %v", err)
	}
	product := ScalarMul(a, inv)
	if product.Cmp(big.NewInt(1)) != 0 {
		t.Errorf("7 * inv(7) must be 1, got %x", product)
	}
}

func TestScalarInvertZeroErrors(t *testing.T) {
	if _, err := ScalarInvert(big.NewInt(0)); err == nil {
		t.Error("ScalarInvert(0) must return an error")
	}
}

func TestPowNExpZeroIsOne(t *testing.T) {
	if PowN(5, 0).Cmp(big.NewInt(1)) != 0 {
		t.Error("5^0 must be 1")
	}
	if PowN(0, 0).Cmp(big.NewInt(1)) != 0 {
		t.Error("0^0 must be 1")
	}
}

func TestPowNExpOneIsBase(t *testing.T) {
	if PowN(3, 1).Cmp(big.NewInt(3)) != 0 {
		t.Error("3^1 must be 3")
	}
}

func TestPowNSquare(t *testing.T) {
	if PowN(2, 8).Cmp(big.NewInt(256)) != 0 {
		t.Error("2^8 must be 256")
	}
}

// ── Point operations ──────────────────────────────────────────────────────────

// known secp256k1 generator
const gx = "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
const gHex = "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"

func TestScalarBaseMultiOneIsGenerator(t *testing.T) {
	g := ScalarBaseMulti(big.NewInt(1))
	if g.X.Text(16) != "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" {
		t.Errorf("1*G x-coord mismatch: %x", g.X)
	}
}

func TestLiftX32ByteGivesEvenY(t *testing.T) {
	xBytes := make([]byte, 32)
	xBig, _ := new(big.Int).SetString(gx, 16)
	copy(xBytes[32-len(xBig.Bytes()):], xBig.Bytes())
	pt, err := LiftX(xBytes)
	if err != nil {
		t.Fatalf("LiftX 32-byte failed: %v", err)
	}
	if !HasEvenY(pt) {
		t.Error("LiftX of x-only must produce even-Y point")
	}
}

func TestLiftX33BytePreservesPrefix(t *testing.T) {
	g := ScalarBaseMulti(big.NewInt(1))
	ser := SerializePoint(g)
	pt, err := LiftX(ser[:])
	if err != nil {
		t.Fatalf("LiftX 33-byte failed: %v", err)
	}
	if pt.X.Cmp(g.X) != 0 || pt.Y.Cmp(g.Y) != 0 {
		t.Error("LiftX 33-byte round-trip must reproduce original point")
	}
}

func TestLiftXOddPrefixDecodes(t *testing.T) {
	// Build a 0x03-prefixed point (negation of generator has odd Y)
	g := ScalarBaseMulti(big.NewInt(1))
	neg := NegatePoint(g)
	ser := SerializePoint(neg)
	if ser[0] != 0x03 {
		t.Skip("negated generator is not odd-Y in this environment")
	}
	pt, err := LiftX(ser[:])
	if err != nil {
		t.Fatalf("LiftX odd prefix failed: %v", err)
	}
	if HasEvenY(pt) {
		t.Error("0x03-prefixed point must have odd Y")
	}
}

func TestLiftXInvalidLengthErrors(t *testing.T) {
	if _, err := LiftX(make([]byte, 31)); err == nil {
		t.Error("LiftX 31 bytes must error")
	}
	if _, err := LiftX(make([]byte, 34)); err == nil {
		t.Error("LiftX 34 bytes must error")
	}
}

func TestSerializeDeserializeRoundtrip(t *testing.T) {
	g := ScalarBaseMulti(big.NewInt(1))
	ser := SerializePoint(g)
	pt, err := DeserializePoint(ser)
	if err != nil {
		t.Fatalf("DeserializePoint failed: %v", err)
	}
	if pt.X.Cmp(g.X) != 0 || pt.Y.Cmp(g.Y) != 0 {
		t.Error("serialize/deserialize round-trip must reproduce original point")
	}
}

func TestGeneratorHasEvenY(t *testing.T) {
	g := ScalarBaseMulti(big.NewInt(1))
	if !HasEvenY(g) {
		t.Error("secp256k1 generator must have even Y")
	}
}

func TestNegatePointFlipsParity(t *testing.T) {
	g := ScalarBaseMulti(big.NewInt(1))
	neg := NegatePoint(g)
	if HasEvenY(neg) == HasEvenY(g) {
		t.Error("negated point must have opposite parity from original")
	}
	// double negation is identity
	dbl := NegatePoint(neg)
	if dbl.X.Cmp(g.X) != 0 || dbl.Y.Cmp(g.Y) != 0 {
		t.Error("negate(negate(G)) must equal G")
	}
}

func TestElementAddBothNilErrors(t *testing.T) {
	if _, err := ElementAdd(nil, nil); err == nil {
		t.Error("ElementAdd(nil, nil) must error")
	}
}

func TestElementAddNilLeftReturnsRight(t *testing.T) {
	g := ScalarBaseMulti(big.NewInt(1))
	result, err := ElementAdd(nil, g)
	if err != nil {
		t.Fatalf("ElementAdd(nil, G) failed: %v", err)
	}
	if result.X.Cmp(g.X) != 0 {
		t.Error("ElementAdd(nil, G) must return G")
	}
}

func TestElementAddNilRightReturnsLeft(t *testing.T) {
	g := ScalarBaseMulti(big.NewInt(1))
	result, err := ElementAdd(g, nil)
	if err != nil {
		t.Fatalf("ElementAdd(G, nil) failed: %v", err)
	}
	if result.X.Cmp(g.X) != 0 {
		t.Error("ElementAdd(G, nil) must return G")
	}
}

func TestElementAddDoubleEqualsPointDouble(t *testing.T) {
	g := ScalarBaseMulti(big.NewInt(1))
	g2add, err := ElementAdd(g, g)
	if err != nil {
		t.Fatalf("ElementAdd(G, G) failed: %v", err)
	}
	g2mul := ScalarBaseMulti(big.NewInt(2))
	if g2add.X.Cmp(g2mul.X) != 0 || g2add.Y.Cmp(g2mul.Y) != 0 {
		t.Error("G+G must equal 2*G")
	}
}

func TestElementAdd2GPlusMinus2GIsInfinity(t *testing.T) {
	g2 := ScalarBaseMulti(big.NewInt(2))
	neg := NegatePoint(g2)
	if _, err := ElementAdd(g2, neg); err == nil {
		t.Error("P + (-P) must return point-at-infinity error")
	}
}

func TestScalarMultiMatchesBaseMulti(t *testing.T) {
	g := ScalarBaseMulti(big.NewInt(1))
	r1 := ScalarMulti(g, big.NewInt(7))
	r2 := ScalarBaseMulti(big.NewInt(7))
	if r1.X.Cmp(r2.X) != 0 || r1.Y.Cmp(r2.Y) != 0 {
		t.Error("scalar_multi(G, 7) must equal scalar_base_multi(7)")
	}
}

func TestSerializeScalarU32(t *testing.T) {
	var zero [32]byte
	if SerializeScalarU32(0) != zero {
		t.Error("SerializeScalarU32(0) must be all zeros")
	}
	one := SerializeScalarU32(1)
	if one[31] != 1 {
		t.Errorf("SerializeScalarU32(1) last byte must be 1, got %d", one[31])
	}
	// 0x01020304 in big-endian at offset 28
	large := SerializeScalarU32(0x01020304)
	if large[28] != 0x01 || large[29] != 0x02 || large[30] != 0x03 || large[31] != 0x04 {
		t.Errorf("SerializeScalarU32(0x01020304) encoding wrong: %x", large)
	}
}

// ── Hash functions ────────────────────────────────────────────────────────────

func TestH1H2H3DifferForSameInput(t *testing.T) {
	msg := []byte("test")
	h1 := H1(msg)
	h2 := H2(msg)
	h3 := H3(msg)
	if h1 == h2 {
		t.Error("H1 and H2 must differ for the same input")
	}
	if h1 == h3 {
		t.Error("H1 and H3 must differ for the same input")
	}
	if h2 == h3 {
		t.Error("H2 and H3 must differ for the same input")
	}
}

func TestH4H5DifferForSameInput(t *testing.T) {
	msg := []byte("test")
	if H4(msg) == H5(msg) {
		t.Error("H4 and H5 must differ for the same input")
	}
}

func TestH3KnownValue(t *testing.T) {
	// hidden_sn for fixture share[1]: H3(hidden_seed || share1_seckey)
	// From the fixture: hidden_sn = "189aeb1bf3a453673cb144a459f0b644183ff02808cad807b672067da4f33357"
	shareSeckey := mustHex32("0e74411caa9ef5ba058d0ccf4e54e1ee773e625fb7d6258097466cedab0de152")
	hiddenSeed := mustHex32("0070ca75929ca1ec4cd70ac34f46079bdfdd87f9d0c0bf4275f3882f7b462d0f")
	var input [64]byte
	copy(input[:32], hiddenSeed[:])
	copy(input[32:], shareSeckey[:])
	result := H3(input[:])
	want := "189aeb1bf3a453673cb144a459f0b644183ff02808cad807b672067da4f33357"
	if toHex(result[:]) != want {
		t.Errorf("H3 known value mismatch:\n  got  %s\n  want %s", toHex(result[:]), want)
	}
}

func TestHash340TaggedHash(t *testing.T) {
	// Same tag, different data → different outputs
	a := Hash340("BIP0340/challenge", [][]byte{[]byte("aaa")})
	b := Hash340("BIP0340/challenge", [][]byte{[]byte("bbb")})
	if a == b {
		t.Error("Hash340 with different data must differ")
	}
	// Different tags → different outputs
	c := Hash340("BIP0340/other", [][]byte{[]byte("aaa")})
	if a == c {
		t.Error("Hash340 with different tags must differ")
	}
	// Same inputs → same output (deterministic)
	a2 := Hash340("BIP0340/challenge", [][]byte{[]byte("aaa")})
	if a != a2 {
		t.Error("Hash340 must be deterministic")
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func mustHex32(s string) [32]byte {
	b := decodeHex(s)
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
		hi := nibble(s[i*2])
		lo := nibble(s[i*2+1])
		b[i] = hi<<4 | lo
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
