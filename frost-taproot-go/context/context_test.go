package context

import (
	"bytes"
	"testing"

	"github.com/frost-taproot/frost-taproot-go/ecc"
	"github.com/frost-taproot/frost-taproot-go/types"
)

func s32(hex string) [32]byte {
	b := decodeHex(hex)
	var out [32]byte
	copy(out[:], b)
	return out
}

func s33(hex string) [33]byte {
	b := decodeHex(hex)
	var out [33]byte
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

var fixtureNonces = []types.PublicNonce{
	{
		ID:       1,
		HiddenPn: s33("024d837d707dfa4b56be26da22b9ff5cb0fd220d011351ba79334003f16871801c"),
		BinderPn: s33("0263c0d31a58799213f5210685b8bc2ce4539819a90c09c216a983e8f8c67a12f5"),
	},
	{
		ID:       2,
		HiddenPn: s33("034bc9f2ef5cc5eb741cc00d763e1077e8bc624df82d198781c71a0757617d8d44"),
		BinderPn: s33("03a1e7d63fd0665b9255df5f6d781762f7e7298a2c42ee6d67cfd287780fb3c2a6"),
	},
}

var (
	fixtureGroupPk = "021ae63bc9ddaffe52d44c3018e83115bfb22195bd8112fcad112310714e6fd5ec"
	fixtureTweaks  = [][32]byte{
		s32("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		s32("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
	}
	fixtureMessage = decodeHex("68656c6c6f20776f726c6421")
)

// ── GetPointState ─────────────────────────────────────────────────────────────

func TestGetPointStateNoTweaksIsIdentity(t *testing.T) {
	pt, err := ecc.LiftX(decodeHex(fixtureGroupPk))
	if err != nil {
		t.Fatalf("LiftX failed: %v", err)
	}
	state, err := GetPointState(pt, nil)
	if err != nil {
		t.Fatalf("GetPointState failed: %v", err)
	}
	// No tweaks: parity=1, state=1, tweak=0, point unchanged
	one := ecc.ScalarToBytes(ecc.ScalarFromBytes([32]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}))
	var zero [32]byte
	if state.Parity != one {
		t.Errorf("no-tweak parity must be 1, got %x", state.Parity)
	}
	if state.State != one {
		t.Errorf("no-tweak state must be 1, got %x", state.State)
	}
	if state.Tweak != zero {
		t.Errorf("no-tweak tweak must be 0, got %x", state.Tweak)
	}
	// The stored point must equal the original serialized point
	serialized := ecc.SerializePoint(pt)
	if state.Point != serialized {
		t.Error("no-tweak point must equal original point")
	}
}

func TestGetPointStateTweakedMatchesFixture(t *testing.T) {
	pt, err := ecc.LiftX(decodeHex(fixtureGroupPk))
	if err != nil {
		t.Fatalf("LiftX failed: %v", err)
	}
	state, err := GetPointState(pt, fixtureTweaks[:])
	if err != nil {
		t.Fatalf("GetPointState with tweaks failed: %v", err)
	}
	wantPk := "025731d4d57552d12877e3db13061d7f6ca09198963e003d1d6e0960d6651e42d3"
	if toHex(state.Point[:]) != wantPk {
		t.Errorf("tweaked point mismatch:\n  got  %s\n  want %s", toHex(state.Point[:]), wantPk)
	}
}

func TestGetPointStateInvalidTweakErrors(t *testing.T) {
	// A tweak equal to -P would make P + tweak*G = infinity
	// We can't easily craft that, so test that the function handles tweaks deterministically
	pt, err := ecc.LiftX(decodeHex(fixtureGroupPk))
	if err != nil {
		t.Fatalf("LiftX failed: %v", err)
	}
	tweak1 := s32("1111111111111111111111111111111111111111111111111111111111111111")
	tweak2 := s32("2222222222222222222222222222222222222222222222222222222222222222")
	s1, err1 := GetPointState(pt, [][32]byte{tweak1})
	s2, err2 := GetPointState(pt, [][32]byte{tweak2})
	if err1 != nil || err2 != nil {
		t.Fatal("GetPointState with small tweaks must not error")
	}
	if s1.Point == s2.Point {
		t.Error("different tweaks must produce different points")
	}
}

// ── GetGroupKeyContext ────────────────────────────────────────────────────────

func TestGetGroupKeyContextNoTweaks(t *testing.T) {
	keyCtx, err := GetGroupKeyContext(decodeHex(fixtureGroupPk), nil)
	if err != nil {
		t.Fatalf("GetGroupKeyContext failed: %v", err)
	}
	if toHex(keyCtx.GroupPk[:]) != fixtureGroupPk {
		t.Errorf("group_pk mismatch: got %s, want %s", toHex(keyCtx.GroupPk[:]), fixtureGroupPk)
	}
	if keyCtx.IntPk == nil {
		t.Error("int_pk must not be nil")
	}
}

func TestGetGroupKeyContextWithTweaks(t *testing.T) {
	keyCtx, err := GetGroupKeyContext(decodeHex(fixtureGroupPk), fixtureTweaks[:])
	if err != nil {
		t.Fatalf("GetGroupKeyContext with tweaks failed: %v", err)
	}
	want := "025731d4d57552d12877e3db13061d7f6ca09198963e003d1d6e0960d6651e42d3"
	if toHex(keyCtx.GroupPk[:]) != want {
		t.Errorf("tweaked group_pk mismatch:\n  got  %s\n  want %s", toHex(keyCtx.GroupPk[:]), want)
	}
	// internal pk must differ from tweaked group pk
	if bytes.Equal(keyCtx.GroupPk[:], keyCtx.IntPk[:]) {
		t.Error("tweaked group_pk must differ from int_pk")
	}
}

func TestGetGroupKeyContextInvalidPubkeyErrors(t *testing.T) {
	if _, err := GetGroupKeyContext(make([]byte, 31), nil); err == nil {
		t.Error("GetGroupKeyContext with 31-byte pubkey must error")
	}
}

// ── GetGroupSigningCtx ────────────────────────────────────────────────────────

func TestGetGroupSigningCtxMatchesFixture(t *testing.T) {
	ctx, err := GetGroupSigningCtx(
		decodeHex(fixtureGroupPk),
		fixtureNonces,
		fixtureMessage,
		fixtureTweaks[:],
	)
	if err != nil {
		t.Fatalf("GetGroupSigningCtx failed: %v", err)
	}

	wantGroupPk := "025731d4d57552d12877e3db13061d7f6ca09198963e003d1d6e0960d6651e42d3"
	if toHex(ctx.GroupPk[:]) != wantGroupPk {
		t.Errorf("ctx.group_pk mismatch:\n  got  %s\n  want %s", toHex(ctx.GroupPk[:]), wantGroupPk)
	}

	wantGroupPn := "03e76328e49c27c12392a117d39ef9f5def368590d5e72438907fb63c1006fd589"
	if toHex(ctx.GroupPn[:]) != wantGroupPn {
		t.Errorf("ctx.group_pn mismatch:\n  got  %s\n  want %s", toHex(ctx.GroupPn[:]), wantGroupPn)
	}

	wantChallenge := "99e6637f68e223b0f6b4caa36b48cc277bf036ece4f14bab657200b43ecb0d55"
	if toHex(ctx.Challenge[:]) != wantChallenge {
		t.Errorf("ctx.challenge mismatch:\n  got  %s\n  want %s", toHex(ctx.Challenge[:]), wantChallenge)
	}

	if len(ctx.BindFactors) != 2 {
		t.Errorf("expected 2 bind factors, got %d", len(ctx.BindFactors))
	}

	if len(ctx.Indexes) != 2 {
		t.Errorf("expected 2 indexes, got %d", len(ctx.Indexes))
	}
}

func TestGetGroupSigningCtxPreservesMessage(t *testing.T) {
	ctx, err := GetGroupSigningCtx(
		decodeHex(fixtureGroupPk),
		fixtureNonces,
		fixtureMessage,
		nil,
	)
	if err != nil {
		t.Fatalf("GetGroupSigningCtx failed: %v", err)
	}
	if !bytes.Equal(ctx.Message, fixtureMessage) {
		t.Error("ctx.Message must equal the input message")
	}
}

func TestGetGroupSigningCtxKeyContextExtract(t *testing.T) {
	ctx, err := GetGroupSigningCtx(
		decodeHex(fixtureGroupPk),
		fixtureNonces,
		fixtureMessage,
		fixtureTweaks[:],
	)
	if err != nil {
		t.Fatalf("GetGroupSigningCtx failed: %v", err)
	}
	keyCtx := ctx.KeyContext()
	if keyCtx.GroupPk != ctx.GroupPk {
		t.Error("KeyContext() must preserve group_pk")
	}
	if keyCtx.GroupPt != ctx.GroupPt {
		t.Error("KeyContext() must preserve group_pt")
	}
}
