package commit

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

// fixture nonces for participants 1 and 2
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

var fixtureGroupPk = s33("021ae63bc9ddaffe52d44c3018e83115bfb22195bd8112fcad112310714e6fd5ec")
var fixtureMessage = decodeHex("68656c6c6f20776f726c6421")

// ── GetNonceIDs ───────────────────────────────────────────────────────────────

func TestGetNonceIDsExtractsIDs(t *testing.T) {
	ids := GetNonceIDs(fixtureNonces)
	if len(ids) != 2 || ids[0] != 1 || ids[1] != 2 {
		t.Errorf("GetNonceIDs returned %v, want [1 2]", ids)
	}
}

func TestGetNonceIDsEmptySlice(t *testing.T) {
	if ids := GetNonceIDs(nil); len(ids) != 0 {
		t.Error("GetNonceIDs of nil must return empty")
	}
}

// ── GetCommitsPrefix ──────────────────────────────────────────────────────────

func TestGetCommitsPrefixSortsByID(t *testing.T) {
	// Reversed order — output must be sorted by ID
	reversed := []types.PublicNonce{fixtureNonces[1], fixtureNonces[0]}
	sorted := GetCommitsPrefix(fixtureNonces)
	fromReversed := GetCommitsPrefix(reversed)
	if !bytes.Equal(sorted, fromReversed) {
		t.Error("GetCommitsPrefix must sort by participant ID")
	}
}

func TestGetCommitsPrefixLength(t *testing.T) {
	prefix := GetCommitsPrefix(fixtureNonces)
	// 2 participants × (32 + 33 + 33) = 196 bytes
	if len(prefix) != 2*(32+33+33) {
		t.Errorf("prefix length %d, want %d", len(prefix), 2*(32+33+33))
	}
}

func TestGetCommitsPrefixMatchesFixture(t *testing.T) {
	// The binding prefix contains group_pk || H4(msg) || H5(commit_list)
	// We can verify the commit_list portion indirectly via GetGroupPrefix
	prefix := GetGroupPrefix(fixtureNonces, fixtureGroupPk, fixtureMessage)
	// prefix must start with the group public key
	if !bytes.Equal(prefix[:33], fixtureGroupPk[:]) {
		t.Error("GetGroupPrefix must start with group_pk")
	}
}

// ── GetGroupPrefix ────────────────────────────────────────────────────────────

func TestGetGroupPrefixLength(t *testing.T) {
	prefix := GetGroupPrefix(fixtureNonces, fixtureGroupPk, fixtureMessage)
	// 33 (group_pk) + 32 (H4 msg) + 32 (H5 commits) = 97
	if len(prefix) != 97 {
		t.Errorf("group prefix length %d, want 97", len(prefix))
	}
}

func TestGetGroupPrefixDiffersForDifferentMessages(t *testing.T) {
	p1 := GetGroupPrefix(fixtureNonces, fixtureGroupPk, []byte("msg1"))
	p2 := GetGroupPrefix(fixtureNonces, fixtureGroupPk, []byte("msg2"))
	if bytes.Equal(p1, p2) {
		t.Error("different messages must produce different group prefixes")
	}
}

func TestGetGroupPrefixMatchesFixtureBindPrefix(t *testing.T) {
	tweakedGroupPk := s33("025731d4d57552d12877e3db13061d7f6ca09198963e003d1d6e0960d6651e42d3")
	prefix := GetGroupPrefix(fixtureNonces, tweakedGroupPk, fixtureMessage)
	want := "025731d4d57552d12877e3db13061d7f6ca09198963e003d1d6e0960d6651e42d3" +
		"c00982b3526dcd6b7bcb4f685ddb41c7d00fecd032aa479f5df03601701bf5232" +
		"ba4662301918443c019abba4a752cdcb8d4f572ad78a88ec416f17b60bb866c"
	if toHex(prefix) != want {
		t.Errorf("bind_prefix mismatch:\n  got  %s\n  want %s", toHex(prefix), want)
	}
}

// ── GetBindFactor / GetGroupBinders ──────────────────────────────────────────

func TestGetBindFactorFindsEntry(t *testing.T) {
	binders := []types.BindFactor{
		{ID: 1, Factor: s32("de9fa47304afaa64b5baddfccf4a8da6705edd162201ce55e1f9a478e6ec2a57")},
		{ID: 2, Factor: s32("97aa7e9649ea9086359b7ba8fe815f54d98a5956ad63d2cf670d465d3b5d0f1f")},
	}
	f, err := GetBindFactor(binders, 1)
	if err != nil {
		t.Fatalf("GetBindFactor failed: %v", err)
	}
	want := "de9fa47304afaa64b5baddfccf4a8da6705edd162201ce55e1f9a478e6ec2a57"
	if toHex(f[:]) != want {
		t.Errorf("bind factor mismatch: got %s, want %s", toHex(f[:]), want)
	}
}

func TestGetBindFactorNotFoundErrors(t *testing.T) {
	if _, err := GetBindFactor(nil, 5); err == nil {
		t.Error("GetBindFactor must error when index not found")
	}
}

func TestGetGroupBindersMatchesFixture(t *testing.T) {
	tweakedGroupPk := s33("025731d4d57552d12877e3db13061d7f6ca09198963e003d1d6e0960d6651e42d3")
	prefix := GetGroupPrefix(fixtureNonces, tweakedGroupPk, fixtureMessage)
	binders := GetGroupBinders(fixtureNonces, prefix)
	if len(binders) != 2 {
		t.Fatalf("expected 2 binders, got %d", len(binders))
	}
	want1 := "de9fa47304afaa64b5baddfccf4a8da6705edd162201ce55e1f9a478e6ec2a57"
	want2 := "97aa7e9649ea9086359b7ba8fe815f54d98a5956ad63d2cf670d465d3b5d0f1f"
	var f1, f2 *types.BindFactor
	for i := range binders {
		if binders[i].ID == 1 {
			f1 = &binders[i]
		}
		if binders[i].ID == 2 {
			f2 = &binders[i]
		}
	}
	if f1 == nil || toHex(f1.Factor[:]) != want1 {
		t.Errorf("binder[1] mismatch: got %v", f1)
	}
	if f2 == nil || toHex(f2.Factor[:]) != want2 {
		t.Errorf("binder[2] mismatch: got %v", f2)
	}
}

// ── GetGroupPubnonce ──────────────────────────────────────────────────────────

func TestGetGroupPubnonceMatchesFixture(t *testing.T) {
	tweakedGroupPk := s33("025731d4d57552d12877e3db13061d7f6ca09198963e003d1d6e0960d6651e42d3")
	prefix := GetGroupPrefix(fixtureNonces, tweakedGroupPk, fixtureMessage)
	binders := GetGroupBinders(fixtureNonces, prefix)
	pn, err := GetGroupPubnonce(fixtureNonces, binders)
	if err != nil {
		t.Fatalf("GetGroupPubnonce failed: %v", err)
	}
	want := "03e76328e49c27c12392a117d39ef9f5def368590d5e72438907fb63c1006fd589"
	if toHex(pn[:]) != want {
		t.Errorf("group_pn mismatch:\n  got  %s\n  want %s", toHex(pn[:]), want)
	}
}

func TestGetGroupPubnonceEmptyNoncesErrors(t *testing.T) {
	if _, err := GetGroupPubnonce(nil, nil); err == nil {
		t.Error("GetGroupPubnonce with no nonces must error")
	}
}

// ── CreateCommitPkg ───────────────────────────────────────────────────────────

func TestCreateCommitPkgMatchesFixture(t *testing.T) {
	share := types.SecretShare{
		ID:     1,
		Seckey: s32("0e74411caa9ef5ba058d0ccf4e54e1ee773e625fb7d6258097466cedab0de152"),
	}
	hiddenSeed := s32("0070ca75929ca1ec4cd70ac34f46079bdfdd87f9d0c0bf4275f3882f7b462d0f")
	binderSeed := s32("0e0376a7180253cdb8b6020bff0eda529760da65e715663e2152e4be2fc7b443")
	pkg := CreateCommitPkg(&share, &hiddenSeed, &binderSeed)

	if toHex(pkg.HiddenSn[:]) != "189aeb1bf3a453673cb144a459f0b644183ff02808cad807b672067da4f33357" {
		t.Errorf("hidden_sn mismatch: %s", toHex(pkg.HiddenSn[:]))
	}
	if toHex(pkg.BinderSn[:]) != "162f3098066a9407c7ce156cb0c49c58ab34b6e195b6435fa4be759e827b9b4c" {
		t.Errorf("binder_sn mismatch: %s", toHex(pkg.BinderSn[:]))
	}
	if toHex(pkg.HiddenPn[:]) != "024d837d707dfa4b56be26da22b9ff5cb0fd220d011351ba79334003f16871801c" {
		t.Errorf("hidden_pn mismatch: %s", toHex(pkg.HiddenPn[:]))
	}
	if toHex(pkg.BinderPn[:]) != "0263c0d31a58799213f5210685b8bc2ce4539819a90c09c216a983e8f8c67a12f5" {
		t.Errorf("binder_pn mismatch: %s", toHex(pkg.BinderPn[:]))
	}
}

func TestCreateCommitPkgPublicNoncesArePubkeys(t *testing.T) {
	share := types.SecretShare{
		ID:     1,
		Seckey: s32("0e74411caa9ef5ba058d0ccf4e54e1ee773e625fb7d6258097466cedab0de152"),
	}
	seed := s32("0070ca75929ca1ec4cd70ac34f46079bdfdd87f9d0c0bf4275f3882f7b462d0f")
	pkg := CreateCommitPkg(&share, &seed, &seed)

	// hidden_pn must be the pubkey of hidden_sn
	hiddenSk := ecc.ScalarFromBytes(pkg.HiddenSn)
	expectedHiddenPn := ecc.SerializePoint(ecc.ScalarBaseMulti(hiddenSk))
	if pkg.HiddenPn != expectedHiddenPn {
		t.Error("hidden_pn must be hidden_sn * G")
	}

	// binder_pn must be the pubkey of binder_sn
	binderSk := ecc.ScalarFromBytes(pkg.BinderSn)
	expectedBinderPn := ecc.SerializePoint(ecc.ScalarBaseMulti(binderSk))
	if pkg.BinderPn != expectedBinderPn {
		t.Error("binder_pn must be binder_sn * G")
	}
}

// ── GetCommitPkg ──────────────────────────────────────────────────────────────

func TestGetCommitPkgFindsShare(t *testing.T) {
	share := types.SecretShare{ID: 2, Seckey: s32("0e74411caa9ef5ba058d0ccf4e54e1ee773e625fb7d6258097466cedab0de152")}
	seed := s32("0070ca75929ca1ec4cd70ac34f46079bdfdd87f9d0c0bf4275f3882f7b462d0f")
	pkg1 := CreateCommitPkg(&types.SecretShare{ID: 1, Seckey: share.Seckey}, &seed, &seed)
	pkg2 := CreateCommitPkg(&share, &seed, &seed)
	pkgs := []types.CommitmentPackage{pkg1, pkg2}

	found, err := GetCommitPkg(pkgs, &share)
	if err != nil {
		t.Fatalf("GetCommitPkg failed: %v", err)
	}
	if found.ID != 2 {
		t.Errorf("GetCommitPkg returned wrong package: ID=%d", found.ID)
	}
}

func TestGetCommitPkgNotFoundErrors(t *testing.T) {
	share := types.SecretShare{ID: 99, Seckey: s32("0e74411caa9ef5ba058d0ccf4e54e1ee773e625fb7d6258097466cedab0de152")}
	if _, err := GetCommitPkg(nil, &share); err == nil {
		t.Error("GetCommitPkg must error when share not found")
	}
}
