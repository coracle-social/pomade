package helpers

import (
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
	shareSeckey = "0e74411caa9ef5ba058d0ccf4e54e1ee773e625fb7d6258097466cedab0de152"
	sharePubkey = "0278f55809a11a1016d13ec4f54674810abe4a6fec8b586e14f90d0c1f80de33eb"
)

// ── GenerateSeckey ───────────────────────────────────────────────────────────

func TestGenerateSeckeyDeterministicWithAux(t *testing.T) {
	aux := s32("0070ca75929ca1ec4cd70ac34f46079bdfdd87f9d0c0bf4275f3882f7b462d0f")
	a := GenerateSeckey(&aux)
	b := GenerateSeckey(&aux)
	if a != b {
		t.Error("GenerateSeckey with same aux must be deterministic")
	}
}

func TestGenerateSeckeyRandomWithoutAux(t *testing.T) {
	a := GenerateSeckey(nil)
	b := GenerateSeckey(nil)
	if a == b {
		t.Error("GenerateSeckey without aux must produce different values each call")
	}
}

func TestGenerateSeckeyIsH3OfAux(t *testing.T) {
	aux := s32("0070ca75929ca1ec4cd70ac34f46079bdfdd87f9d0c0bf4275f3882f7b462d0f")
	result := GenerateSeckey(&aux)
	expected := ecc.H3(aux[:])
	if result != expected {
		t.Error("GenerateSeckey(aux) must equal H3(aux)")
	}
}

// ── GenerateNonce ────────────────────────────────────────────────────────────

func TestGenerateNonceDeterministicWithSeed(t *testing.T) {
	secret := s32(shareSeckey)
	seed := s32("0070ca75929ca1ec4cd70ac34f46079bdfdd87f9d0c0bf4275f3882f7b462d0f")
	a := GenerateNonce(secret, &seed)
	b := GenerateNonce(secret, &seed)
	if a != b {
		t.Error("GenerateNonce with same seed must be deterministic")
	}
}

func TestGenerateNonceMatchesFixture(t *testing.T) {
	secret := s32(shareSeckey)
	seed := s32("0070ca75929ca1ec4cd70ac34f46079bdfdd87f9d0c0bf4275f3882f7b462d0f")
	nonce := GenerateNonce(secret, &seed)
	want := "189aeb1bf3a453673cb144a459f0b644183ff02808cad807b672067da4f33357"
	if toHex(nonce[:]) != want {
		t.Errorf("nonce mismatch:\n  got  %s\n  want %s", toHex(nonce[:]), want)
	}
}

func TestGenerateNonceRandomWithoutSeed(t *testing.T) {
	secret := s32(shareSeckey)
	a := GenerateNonce(secret, nil)
	b := GenerateNonce(secret, nil)
	if a == b {
		t.Error("GenerateNonce without seed must produce different values each call")
	}
}

// ── GetPubkey ────────────────────────────────────────────────────────────────

func TestGetPubkeyMatchesFixture(t *testing.T) {
	seckey := s32(shareSeckey)
	pubkey := GetPubkey(seckey)
	if toHex(pubkey[:]) != sharePubkey {
		t.Errorf("pubkey mismatch:\n  got  %s\n  want %s", toHex(pubkey[:]), sharePubkey)
	}
}

func TestGetPubkeyIsCompressed33Bytes(t *testing.T) {
	seckey := s32(shareSeckey)
	pubkey := GetPubkey(seckey)
	if len(pubkey) != 33 {
		t.Errorf("pubkey must be 33 bytes, got %d", len(pubkey))
	}
	if pubkey[0] != 0x02 && pubkey[0] != 0x03 {
		t.Errorf("pubkey prefix must be 0x02 or 0x03, got %x", pubkey[0])
	}
}

// ── GetChallenge ─────────────────────────────────────────────────────────────

func TestGetChallengeMatchesFixture(t *testing.T) {
	// From the interop fixture signing context
	groupPn := decodeHex("03e76328e49c27c12392a117d39ef9f5def368590d5e72438907fb63c1006fd589")
	groupPk := decodeHex("025731d4d57552d12877e3db13061d7f6ca09198963e003d1d6e0960d6651e42d3")
	message := decodeHex("68656c6c6f20776f726c6421")
	challenge, err := GetChallenge(groupPn, groupPk, message)
	if err != nil {
		t.Fatalf("GetChallenge failed: %v", err)
	}
	want := "99e6637f68e223b0f6b4caa36b48cc277bf036ece4f14bab657200b43ecb0d55"
	got := ecc.ScalarToBytes(challenge)
	if toHex(got[:]) != want {
		t.Errorf("challenge mismatch:\n  got  %s\n  want %s", toHex(got[:]), want)
	}
}

func TestGetChallengeInvalidPnonceErrors(t *testing.T) {
	if _, err := GetChallenge(make([]byte, 31), make([]byte, 33), nil); err == nil {
		t.Error("GetChallenge with 31-byte pnonce must error")
	}
}

func TestGetChallengeInvalidPubkeyErrors(t *testing.T) {
	if _, err := GetChallenge(make([]byte, 33), make([]byte, 31), nil); err == nil {
		t.Error("GetChallenge with 31-byte pubkey must error")
	}
}

// ── ConvertPubkeyToBip340 / ConvertPubkeyToEcdsa ─────────────────────────────

func TestConvertToBip340StripsPrefix(t *testing.T) {
	compressed := decodeHex("021ae63bc9ddaffe52d44c3018e83115bfb22195bd8112fcad112310714e6fd5ec")
	bip340, err := ConvertPubkeyToBip340(compressed)
	if err != nil {
		t.Fatalf("ConvertPubkeyToBip340 failed: %v", err)
	}
	if len(bip340) != 32 {
		t.Errorf("bip340 key must be 32 bytes, got %d", len(bip340))
	}
	for i, b := range bip340 {
		if b != compressed[i+1] {
			t.Errorf("bip340[%d] mismatch", i)
		}
	}
}

func TestConvertToBip340PassthroughFor32Bytes(t *testing.T) {
	xonly := decodeHex("1ae63bc9ddaffe52d44c3018e83115bfb22195bd8112fcad112310714e6fd5ec")
	bip340, err := ConvertPubkeyToBip340(xonly)
	if err != nil {
		t.Fatalf("ConvertPubkeyToBip340 failed: %v", err)
	}
	for i, b := range bip340 {
		if b != xonly[i] {
			t.Error("32-byte input must pass through unchanged")
		}
	}
}

func TestConvertToBip340InvalidLengthErrors(t *testing.T) {
	if _, err := ConvertPubkeyToBip340(make([]byte, 31)); err == nil {
		t.Error("ConvertPubkeyToBip340 with 31 bytes must error")
	}
	if _, err := ConvertPubkeyToBip340(make([]byte, 34)); err == nil {
		t.Error("ConvertPubkeyToBip340 with 34 bytes must error")
	}
}

func TestConvertToEcdsaPrependsPrefix(t *testing.T) {
	xonly := decodeHex("1ae63bc9ddaffe52d44c3018e83115bfb22195bd8112fcad112310714e6fd5ec")
	ecdsa, err := ConvertPubkeyToEcdsa(xonly)
	if err != nil {
		t.Fatalf("ConvertPubkeyToEcdsa failed: %v", err)
	}
	if len(ecdsa) != 33 {
		t.Errorf("ecdsa key must be 33 bytes, got %d", len(ecdsa))
	}
	if ecdsa[0] != 0x02 {
		t.Errorf("ecdsa prefix must be 0x02, got %x", ecdsa[0])
	}
	for i, b := range xonly {
		if ecdsa[i+1] != b {
			t.Errorf("ecdsa body mismatch at byte %d", i)
		}
	}
}

func TestConvertToEcdsaPassthroughFor33Bytes(t *testing.T) {
	compressed := decodeHex("021ae63bc9ddaffe52d44c3018e83115bfb22195bd8112fcad112310714e6fd5ec")
	ecdsa, err := ConvertPubkeyToEcdsa(compressed)
	if err != nil {
		t.Fatalf("ConvertPubkeyToEcdsa failed: %v", err)
	}
	for i, b := range ecdsa {
		if b != compressed[i] {
			t.Error("33-byte input must pass through unchanged")
		}
	}
}

func TestConvertToEcdsaInvalidLengthErrors(t *testing.T) {
	if _, err := ConvertPubkeyToEcdsa(make([]byte, 31)); err == nil {
		t.Error("ConvertPubkeyToEcdsa with 31 bytes must error")
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func decodeHex(s string) []byte {
	b := make([]byte, len(s)/2)
	for i := range b {
		b[i] = nibble(s[i*2])<<4 | nibble(s[i*2+1])
	}
	return b
}
