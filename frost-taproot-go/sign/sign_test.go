package sign

import (
	"testing"

	"github.com/frost-taproot/frost-taproot-go/context"
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

var fixtureTweaks = [][32]byte{
	s32("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
	s32("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
}

var fixtureMessage = decodeHex("68656c6c6f20776f726c6421")
var fixtureGroupPk = "021ae63bc9ddaffe52d44c3018e83115bfb22195bd8112fcad112310714e6fd5ec"

func buildCtx(t *testing.T) types.GroupSigningCtx {
	t.Helper()
	ctx, err := context.GetGroupSigningCtx(
		decodeHex(fixtureGroupPk),
		fixtureNonces,
		fixtureMessage,
		fixtureTweaks[:],
	)
	if err != nil {
		t.Fatalf("GetGroupSigningCtx failed: %v", err)
	}
	return ctx
}

// ── SignMsg ───────────────────────────────────────────────────────────────────

func TestSignMsgMatchesFixtureShare1(t *testing.T) {
	ctx := buildCtx(t)
	share := types.SecretShare{
		ID:     1,
		Seckey: s32("0e74411caa9ef5ba058d0ccf4e54e1ee773e625fb7d6258097466cedab0de152"),
	}
	snonce := types.SecretNonce{
		ID:       1,
		HiddenSn: s32("189aeb1bf3a453673cb144a459f0b644183ff02808cad807b672067da4f33357"),
		BinderSn: s32("162f3098066a9407c7ce156cb0c49c58ab34b6e195b6435fa4be759e827b9b4c"),
	}
	sig, err := SignMsg(&ctx, &share, &snonce)
	if err != nil {
		t.Fatalf("SignMsg failed: %v", err)
	}
	wantPubkey := "0278f55809a11a1016d13ec4f54674810abe4a6fec8b586e14f90d0c1f80de33eb"
	wantPsig := "89ce878d8aa2f6c6565e963c6bbe99c45af811a2892c402b4c4e3f9ad972a48b"
	if toHex(sig.Pubkey[:]) != wantPubkey {
		t.Errorf("psig[1].pubkey mismatch:\n  got  %s\n  want %s", toHex(sig.Pubkey[:]), wantPubkey)
	}
	if toHex(sig.Psig[:]) != wantPsig {
		t.Errorf("psig[1].psig mismatch:\n  got  %s\n  want %s", toHex(sig.Psig[:]), wantPsig)
	}
}

func TestSignMsgMatchesFixtureShare2(t *testing.T) {
	ctx := buildCtx(t)
	share := types.SecretShare{
		ID:     2,
		Seckey: s32("1c77b7c3c2a14987be430edb4d63bc410e9f3cc59eeb8bbeb89951abdad59595"),
	}
	snonce := types.SecretNonce{
		ID:       2,
		HiddenSn: s32("1c48193192f4a7ba98b04f21246da1925fdacd387ac79bb9708062c705f37a17"),
		BinderSn: s32("f3ede9cd66b93ce18af27792521c929c10cf21a45d72892db7d8a5088bd2ea2e"),
	}
	sig, err := SignMsg(&ctx, &share, &snonce)
	if err != nil {
		t.Fatalf("SignMsg failed: %v", err)
	}
	wantPubkey := "02f00d2b4d3b761ed6317310ed791234dfcad643c00000690e9601adc412b1a22d"
	wantPsig := "67488a00fc37386e12eddfd8eee2dcf997fc01255e7ea66f605db448c86363b1"
	if toHex(sig.Pubkey[:]) != wantPubkey {
		t.Errorf("psig[2].pubkey mismatch:\n  got  %s\n  want %s", toHex(sig.Pubkey[:]), wantPubkey)
	}
	if toHex(sig.Psig[:]) != wantPsig {
		t.Errorf("psig[2].psig mismatch:\n  got  %s\n  want %s", toHex(sig.Psig[:]), wantPsig)
	}
}

func TestSignMsgMismatchedIndexErrors(t *testing.T) {
	ctx := buildCtx(t)
	share := types.SecretShare{
		ID:     1,
		Seckey: s32("0e74411caa9ef5ba058d0ccf4e54e1ee773e625fb7d6258097466cedab0de152"),
	}
	snonce := types.SecretNonce{
		ID:       2, // wrong — must match share.ID
		HiddenSn: s32("189aeb1bf3a453673cb144a459f0b644183ff02808cad807b672067da4f33357"),
		BinderSn: s32("162f3098066a9407c7ce156cb0c49c58ab34b6e195b6435fa4be759e827b9b4c"),
	}
	if _, err := SignMsg(&ctx, &share, &snonce); err == nil {
		t.Error("SignMsg with mismatched share/snonce index must return an error")
	}
}

// ── VerifyPartialSig ──────────────────────────────────────────────────────────

func TestVerifyPartialSigAcceptsValidSig(t *testing.T) {
	ctx := buildCtx(t)
	pnonce := &fixtureNonces[0]
	sharePk := s33("0278f55809a11a1016d13ec4f54674810abe4a6fec8b586e14f90d0c1f80de33eb")
	psig := s32("89ce878d8aa2f6c6565e963c6bbe99c45af811a2892c402b4c4e3f9ad972a48b")
	ok, err := VerifyPartialSig(&ctx, pnonce, sharePk, psig)
	if err != nil {
		t.Fatalf("VerifyPartialSig failed: %v", err)
	}
	if !ok {
		t.Error("VerifyPartialSig must accept a valid partial signature")
	}
}

func TestVerifyPartialSigRejectsTamperedSig(t *testing.T) {
	ctx := buildCtx(t)
	pnonce := &fixtureNonces[0]
	sharePk := s33("0278f55809a11a1016d13ec4f54674810abe4a6fec8b586e14f90d0c1f80de33eb")
	psig := s32("89ce878d8aa2f6c6565e963c6bbe99c45af811a2892c402b4c4e3f9ad972a48b")
	psig[0] ^= 0xff // corrupt
	ok, err := VerifyPartialSig(&ctx, pnonce, sharePk, psig)
	if err != nil {
		t.Fatalf("VerifyPartialSig failed: %v", err)
	}
	if ok {
		t.Error("VerifyPartialSig must reject a tampered partial signature")
	}
}

// ── CombinePartialSigs ────────────────────────────────────────────────────────

func TestCombinePartialSigsMatchesFixture(t *testing.T) {
	ctx := buildCtx(t)
	psigs := []types.ShareSignature{
		{
			ID:     1,
			Pubkey: s33("0278f55809a11a1016d13ec4f54674810abe4a6fec8b586e14f90d0c1f80de33eb"),
			Psig:   s32("89ce878d8aa2f6c6565e963c6bbe99c45af811a2892c402b4c4e3f9ad972a48b"),
		},
		{
			ID:     2,
			Pubkey: s33("02f00d2b4d3b761ed6317310ed791234dfcad643c00000690e9601adc412b1a22d"),
			Psig:   s32("67488a00fc37386e12eddfd8eee2dcf997fc01255e7ea66f605db448c86363b1"),
		},
	}
	sig, err := CombinePartialSigs(&ctx, psigs)
	if err != nil {
		t.Fatalf("CombinePartialSigs failed: %v", err)
	}
	want := "e76328e49c27c12392a117d39ef9f5def368590d5e72438907fb63c1006fd5891d715fa750b5840610aaf531949f633c4555ac20caf290c3f22cc0771f074447"
	if toHex(sig[:]) != want {
		t.Errorf("final signature mismatch:\n  got  %s\n  want %s", toHex(sig[:]), want)
	}
}

// ── VerifyFinalSig ────────────────────────────────────────────────────────────

func TestVerifyFinalSigAcceptsValidSignature(t *testing.T) {
	ctx := buildCtx(t)
	psigs := []types.ShareSignature{
		{
			ID:     1,
			Pubkey: s33("0278f55809a11a1016d13ec4f54674810abe4a6fec8b586e14f90d0c1f80de33eb"),
			Psig:   s32("89ce878d8aa2f6c6565e963c6bbe99c45af811a2892c402b4c4e3f9ad972a48b"),
		},
		{
			ID:     2,
			Pubkey: s33("02f00d2b4d3b761ed6317310ed791234dfcad643c00000690e9601adc412b1a22d"),
			Psig:   s32("67488a00fc37386e12eddfd8eee2dcf997fc01255e7ea66f605db448c86363b1"),
		},
	}
	sig, _ := CombinePartialSigs(&ctx, psigs)
	keyCtx := ctx.KeyContext()
	ok, err := VerifyFinalSig(&keyCtx, fixtureMessage, sig)
	if err != nil {
		t.Fatalf("VerifyFinalSig failed: %v", err)
	}
	if !ok {
		t.Error("VerifyFinalSig must accept the combined BIP340 signature")
	}
}

func TestVerifyFinalSigRejectsTamperedSignature(t *testing.T) {
	ctx := buildCtx(t)
	psigs := []types.ShareSignature{
		{
			ID:     1,
			Pubkey: s33("0278f55809a11a1016d13ec4f54674810abe4a6fec8b586e14f90d0c1f80de33eb"),
			Psig:   s32("89ce878d8aa2f6c6565e963c6bbe99c45af811a2892c402b4c4e3f9ad972a48b"),
		},
		{
			ID:     2,
			Pubkey: s33("02f00d2b4d3b761ed6317310ed791234dfcad643c00000690e9601adc412b1a22d"),
			Psig:   s32("67488a00fc37386e12eddfd8eee2dcf997fc01255e7ea66f605db448c86363b1"),
		},
	}
	sig, _ := CombinePartialSigs(&ctx, psigs)
	sig[63] ^= 0xff // corrupt s scalar
	keyCtx := ctx.KeyContext()
	ok, err := VerifyFinalSig(&keyCtx, fixtureMessage, sig)
	if err != nil {
		t.Fatalf("VerifyFinalSig failed unexpectedly: %v", err)
	}
	if ok {
		t.Error("VerifyFinalSig must reject a tampered signature")
	}
}
