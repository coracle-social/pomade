package integration

import (
	"bytes"
	"testing"

	"github.com/frost-taproot/frost-taproot-go/ecc"
	"github.com/frost-taproot/frost-taproot-go/group"
	"github.com/frost-taproot/frost-taproot-go/helpers"
	"github.com/frost-taproot/frost-taproot-go/recover"
	"github.com/frost-taproot/frost-taproot-go/refresh"
	"github.com/frost-taproot/frost-taproot-go/shares"
	"github.com/frost-taproot/frost-taproot-go/types"
)

// ── TweakSeckey ───────────────────────────────────────────────────────────────

// TweakSeckey adds the tweak scalar: (seckey + tweak) mod N.

func TestTweakSeckeyByZeroIsIdentity(t *testing.T) {
	seckey := mustHexTo32("0e74411caa9ef5ba058d0ccf4e54e1ee773e625fb7d6258097466cedab0de152")
	zero := mustHexTo32("0000000000000000000000000000000000000000000000000000000000000000")
	tweaked := helpers.TweakSeckey(seckey, zero)
	if tweaked != seckey {
		t.Error("tweak by zero must be identity")
	}
}

func TestTweakSeckeyByOneIncrementsScalar(t *testing.T) {
	seckey := mustHexTo32("0e74411caa9ef5ba058d0ccf4e54e1ee773e625fb7d6258097466cedab0de152")
	one := mustHexTo32("0000000000000000000000000000000000000000000000000000000000000001")
	tweaked := helpers.TweakSeckey(seckey, one)
	// tweaked = seckey + 1: last byte must be seckey[31] + 1 (no carry in this value)
	if tweaked[31] != seckey[31]+1 {
		t.Errorf("tweak by one: expected last byte %d, got %d", seckey[31]+1, tweaked[31])
	}
	// High bytes unchanged
	if !bytes.Equal(tweaked[:31], seckey[:31]) {
		t.Error("tweak by one: high bytes must be unchanged")
	}
}

// The tweaked secret key must produce the same public key as the tweaked public key.
func TestTweakSeckeyConsistentWithTweakPubkey(t *testing.T) {
	seckey := mustHexTo32("0e74411caa9ef5ba058d0ccf4e54e1ee773e625fb7d6258097466cedab0de152")
	tweak := mustHexTo32("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	pubkey := helpers.GetPubkey(seckey)

	tweakedSk := helpers.TweakSeckey(seckey, tweak)
	tweakedPkFromSk := helpers.GetPubkey(tweakedSk)

	tweakedPkDirect, err := helpers.TweakPubkey(pubkey[:], tweak)
	if err != nil {
		t.Fatalf("TweakPubkey failed: %v", err)
	}

	if !bytes.Equal(tweakedPkFromSk[:], tweakedPkDirect[:]) {
		t.Errorf("tweaked sk pubkey %x != tweaked pk %x", tweakedPkFromSk, tweakedPkDirect)
	}
}

// ── TweakPubkey ───────────────────────────────────────────────────────────────

// TweakPubkey computes pubkey_point + tweak*G.

func TestTweakPubkeyByZeroIsIdentity(t *testing.T) {
	pubkey := mustHexTo33("021ae63bc9ddaffe52d44c3018e83115bfb22195bd8112fcad112310714e6fd5ec")
	zero := mustHexTo32("0000000000000000000000000000000000000000000000000000000000000000")
	// tweak*G = 0*G = identity; pubkey + identity = pubkey
	tweaked, err := helpers.TweakPubkey(pubkey[:], zero)
	if err != nil {
		t.Fatalf("TweakPubkey failed: %v", err)
	}
	if tweaked != pubkey {
		t.Errorf("tweak pubkey by zero: got %x, want %x", tweaked, pubkey)
	}
}

func TestTweakPubkeyByOneAddsGenerator(t *testing.T) {
	pubkey := mustHexTo33("021ae63bc9ddaffe52d44c3018e83115bfb22195bd8112fcad112310714e6fd5ec")
	one := mustHexTo32("0000000000000000000000000000000000000000000000000000000000000001")

	tweaked, err := helpers.TweakPubkey(pubkey[:], one)
	if err != nil {
		t.Fatalf("TweakPubkey failed: %v", err)
	}

	// Compute expected: lift(pubkey) + 1*G
	pt, _ := ecc.LiftX(pubkey[:])
	g := ecc.ScalarBaseMulti(ecc.ScalarFromBytes(one))
	expected, _ := ecc.ElementAdd(pt, g)
	expectedBytes := ecc.SerializePoint(expected)

	if tweaked != expectedBytes {
		t.Errorf("tweak by one: got %x, want %x", tweaked, expectedBytes)
	}
}

func TestTweakPubkeyInvalidLengthErrors(t *testing.T) {
	tweak := mustHexTo32("0000000000000000000000000000000000000000000000000000000000000001")
	if _, err := helpers.TweakPubkey([]byte{0, 1, 2}, tweak); err == nil {
		t.Error("expected error for invalid pubkey length")
	}
}

// ── VerifyShare ───────────────────────────────────────────────────────────────

func TestVerifyShareValidShares(t *testing.T) {
	secrets := [][32]byte{
		mustHexTo32("0070ca75929ca1ec4cd70ac34f46079bdfdd87f9d0c0bf4275f3882f7b462d0f"),
		mustHexTo32("0e0376a7180253cdb8b6020bff0eda529760da65e715663e2152e4be2fc7b443"),
	}
	set, err := group.CreateDealerSet(2, 3, secrets)
	if err != nil {
		t.Fatalf("CreateDealerSet failed: %v", err)
	}
	for _, s := range set.Shares {
		ok, err := shares.VerifyShare(set.VssCommits, &s, 2)
		if err != nil {
			t.Fatalf("VerifyShare error for idx %d: %v", s.ID, err)
		}
		if !ok {
			t.Errorf("share %d should be valid", s.ID)
		}
	}
}

func TestVerifyShareTamperedShareFails(t *testing.T) {
	secrets := [][32]byte{
		mustHexTo32("0070ca75929ca1ec4cd70ac34f46079bdfdd87f9d0c0bf4275f3882f7b462d0f"),
		mustHexTo32("0e0376a7180253cdb8b6020bff0eda529760da65e715663e2152e4be2fc7b443"),
	}
	set, err := group.CreateDealerSet(2, 3, secrets)
	if err != nil {
		t.Fatalf("CreateDealerSet failed: %v", err)
	}
	tampered := set.Shares[0]
	tampered.Seckey[0] ^= 0xff
	ok, err := shares.VerifyShare(set.VssCommits, &tampered, 2)
	if err != nil {
		t.Fatalf("VerifyShare error: %v", err)
	}
	if ok {
		t.Error("tampered share should fail verification")
	}
}

// ── GenRecoveryShares ─────────────────────────────────────────────────────────

func TestGenRecoverySharesReconstructsLostShare(t *testing.T) {
	secrets := [][32]byte{
		mustHexTo32("0070ca75929ca1ec4cd70ac34f46079bdfdd87f9d0c0bf4275f3882f7b462d0f"),
		mustHexTo32("0e0376a7180253cdb8b6020bff0eda529760da65e715663e2152e4be2fc7b443"),
	}
	set, err := group.CreateDealerSet(2, 3, secrets)
	if err != nil {
		t.Fatalf("CreateDealerSet failed: %v", err)
	}

	// Members 2 and 3 help recover share for target=1.
	members := []uint32{2, 3}
	deterSeeds := [][32]byte{mustHexTo32("0070ca75929ca1ec4cd70ac34f46079bdfdd87f9d0c0bf4275f3882f7b462d0f")}

	pkg2, err := recover.GenRecoveryShares(members, &set.Shares[1], 1, 2, deterSeeds)
	if err != nil {
		t.Fatalf("GenRecoveryShares for share 2 failed: %v", err)
	}
	pkg3, err := recover.GenRecoveryShares(members, &set.Shares[2], 1, 2, deterSeeds)
	if err != nil {
		t.Fatalf("GenRecoveryShares for share 3 failed: %v", err)
	}

	// Each helper sends the aggregated contribution to each recipient.
	// agg[idx] = sum of all helpers' repair_shares[idx]
	findShare := func(pkg types.SecretSharePackage, idx uint32) *types.SecretShare {
		for i := range pkg.Shares {
			if pkg.Shares[i].ID == idx {
				return &pkg.Shares[i]
			}
		}
		return nil
	}

	agg2 := types.SecretShare{
		ID: 2,
		Seckey: ecc.ScalarToBytes(ecc.ScalarAdd(
			ecc.ScalarFromBytes(findShare(pkg2, 2).Seckey),
			ecc.ScalarFromBytes(findShare(pkg3, 2).Seckey),
		)),
	}
	agg3 := types.SecretShare{
		ID: 3,
		Seckey: ecc.ScalarToBytes(ecc.ScalarAdd(
			ecc.ScalarFromBytes(findShare(pkg2, 3).Seckey),
			ecc.ScalarFromBytes(findShare(pkg3, 3).Seckey),
		)),
	}

	repaired := recover.RecoverShare([]types.SecretShare{agg2, agg3}, 1)
	if repaired.ID != 1 {
		t.Errorf("expected recovered share idx 1, got %d", repaired.ID)
	}
	if !bytes.Equal(repaired.Seckey[:], set.Shares[0].Seckey[:]) {
		t.Errorf("recovered share must match original:\n  got  %x\n  want %x",
			repaired.Seckey, set.Shares[0].Seckey)
	}
}

func TestGenRecoverySharesMembersExceedThresholdErrors(t *testing.T) {
	secrets := [][32]byte{
		mustHexTo32("0070ca75929ca1ec4cd70ac34f46079bdfdd87f9d0c0bf4275f3882f7b462d0f"),
		mustHexTo32("0e0376a7180253cdb8b6020bff0eda529760da65e715663e2152e4be2fc7b443"),
	}
	set, err := group.CreateDealerSet(2, 3, secrets)
	if err != nil {
		t.Fatalf("CreateDealerSet failed: %v", err)
	}
	// 3 members, threshold 2 → repairShares has 2 entries but sortedMembers has 3
	members := []uint32{2, 3, 4}
	_, err = recover.GenRecoveryShares(members, &set.Shares[1], 1, 2, nil)
	if err == nil {
		t.Error("expected error when member count exceeds threshold")
	}
}

func TestGenRecoverySharesNotEnoughMembersErrors(t *testing.T) {
	secrets := [][32]byte{
		mustHexTo32("0070ca75929ca1ec4cd70ac34f46079bdfdd87f9d0c0bf4275f3882f7b462d0f"),
		mustHexTo32("0e0376a7180253cdb8b6020bff0eda529760da65e715663e2152e4be2fc7b443"),
	}
	set, err := group.CreateDealerSet(2, 3, secrets)
	if err != nil {
		t.Fatalf("CreateDealerSet failed: %v", err)
	}
	// Only 1 member but threshold=2
	_, err = recover.GenRecoveryShares([]uint32{2}, &set.Shares[1], 1, 2, nil)
	if err == nil {
		t.Error("expected error when not enough members")
	}
}

// ── GenRefreshShares / RefreshShare ───────────────────────────────────────────

func TestRefreshSharePreservesSecret(t *testing.T) {
	secrets := [][32]byte{
		mustHexTo32("0070ca75929ca1ec4cd70ac34f46079bdfdd87f9d0c0bf4275f3882f7b462d0f"),
		mustHexTo32("0e0376a7180253cdb8b6020bff0eda529760da65e715663e2152e4be2fc7b443"),
	}
	set, err := group.CreateDealerSet(2, 3, secrets)
	if err != nil {
		t.Fatalf("CreateDealerSet failed: %v", err)
	}

	r0 := mustHexTo32("1111111111111111111111111111111111111111111111111111111111111111")
	r1 := mustHexTo32("2222222222222222222222222222222222222222222222222222222222222222")
	r2 := mustHexTo32("3333333333333333333333333333333333333333333333333333333333333333")

	rp1, err := refresh.GenRefreshShares(1, 2, 3, [][32]byte{r0})
	if err != nil {
		t.Fatalf("GenRefreshShares 1 failed: %v", err)
	}
	rp2, err := refresh.GenRefreshShares(2, 2, 3, [][32]byte{r1})
	if err != nil {
		t.Fatalf("GenRefreshShares 2 failed: %v", err)
	}
	rp3, err := refresh.GenRefreshShares(3, 2, 3, [][32]byte{r2})
	if err != nil {
		t.Fatalf("GenRefreshShares 3 failed: %v", err)
	}

	findShare := func(pkg types.SecretSharePackage, idx uint32) types.SecretShare {
		for _, s := range pkg.Shares {
			if s.ID == idx {
				return s
			}
		}
		t.Fatalf("share %d not found", idx)
		return types.SecretShare{}
	}

	agg1 := []types.SecretShare{findShare(rp1, 1), findShare(rp2, 1), findShare(rp3, 1)}
	agg2 := []types.SecretShare{findShare(rp1, 2), findShare(rp2, 2), findShare(rp3, 2)}

	new1, err := refresh.RefreshShare(agg1, &set.Shares[0])
	if err != nil {
		t.Fatalf("RefreshShare 1 failed: %v", err)
	}
	new2, err := refresh.RefreshShare(agg2, &set.Shares[1])
	if err != nil {
		t.Fatalf("RefreshShare 2 failed: %v", err)
	}

	recovered, err := shares.DeriveSharesSecret([]types.SecretShare{new1, new2})
	if err != nil {
		t.Fatalf("DeriveSharesSecret failed: %v", err)
	}
	if !bytes.Equal(recovered[:], secrets[0][:]) {
		t.Errorf("secret must be unchanged after refresh:\n  got  %x\n  want %x",
			recovered, secrets[0])
	}
}

func TestRefreshShareChangesShareValues(t *testing.T) {
	secrets := [][32]byte{
		mustHexTo32("0070ca75929ca1ec4cd70ac34f46079bdfdd87f9d0c0bf4275f3882f7b462d0f"),
		mustHexTo32("0e0376a7180253cdb8b6020bff0eda529760da65e715663e2152e4be2fc7b443"),
	}
	set, err := group.CreateDealerSet(2, 3, secrets)
	if err != nil {
		t.Fatalf("CreateDealerSet failed: %v", err)
	}

	r0 := mustHexTo32("1111111111111111111111111111111111111111111111111111111111111111")
	rp1, err := refresh.GenRefreshShares(1, 2, 3, [][32]byte{r0})
	if err != nil {
		t.Fatalf("GenRefreshShares failed: %v", err)
	}

	agg1 := []types.SecretShare{}
	for _, s := range rp1.Shares {
		if s.ID == 1 {
			agg1 = append(agg1, s)
		}
	}

	new1, err := refresh.RefreshShare(agg1, &set.Shares[0])
	if err != nil {
		t.Fatalf("RefreshShare failed: %v", err)
	}
	if bytes.Equal(new1.Seckey[:], set.Shares[0].Seckey[:]) {
		t.Error("refreshed share should differ from original")
	}
	if new1.ID != set.Shares[0].ID {
		t.Errorf("refreshed share idx must match: got %d, want %d", new1.ID, set.Shares[0].ID)
	}
}

func TestRefreshSharePolynomialHasZeroConstantTerm(t *testing.T) {
	r0 := mustHexTo32("1111111111111111111111111111111111111111111111111111111111111111")
	pkg, err := refresh.GenRefreshShares(1, 2, 3, [][32]byte{r0})
	if err != nil {
		t.Fatalf("GenRefreshShares failed: %v", err)
	}

	// Interpolate the refresh shares to recover f(0). It must be zero.
	recovered, err := shares.DeriveSharesSecret(pkg.Shares)
	if err != nil {
		t.Fatalf("DeriveSharesSecret failed: %v", err)
	}
	var zero [32]byte
	if !bytes.Equal(recovered[:], zero[:]) {
		t.Errorf("refresh polynomial f(0) must be zero, got %x", recovered)
	}
}
