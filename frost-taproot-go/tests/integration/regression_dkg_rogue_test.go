package integration

// Regression test for the DKG rogue-key attack.
//
// Original bug: DkgFinalize set the group key to the unauthenticated sum of every
// participant's VssCommits[0]. With no proof of possession and no
// commit-then-reveal round, a participant broadcasting last could choose its
// commitments as f = w - S*L0 (S*G = sum of the honest constant commitments),
// cancelling the honest contributions so the group key became l*G for an l it
// knew, while every honest share still verified.
//
// Fix: each Round-1 commitment now carries a Schnorr proof of possession of the
// discrete log of VssCommits[0], bound to the participant index, and DkgFinalize
// verifies every PoP before folding any commitment into the group key. The
// crafted cancelling commitment has unknown discrete log, so no valid PoP exists
// for it — the attacker's strongest move is to attach a genuine PoP for a
// different point it controls, which fails because the PoP is bound to the
// (index, commitment) it is presented with.

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/frost-taproot/frost-taproot-go/ecc"
	"github.com/frost-taproot/frost-taproot-go/frost"
	"github.com/frost-taproot/frost-taproot-go/helpers"
	"github.com/frost-taproot/frost-taproot-go/poly"
	"github.com/frost-taproot/frost-taproot-go/shares"
	"github.com/frost-taproot/frost-taproot-go/types"
)

func evalCoeffs(coeffs []*big.Int, i uint32) *big.Int {
	v, err := poly.EvaluateX(coeffs, poly.IndexToScalar(i))
	if err != nil {
		panic(err)
	}
	return v
}

// polyFromRoots returns monic coefficients (low->high) of prod(z - r) mod N.
func polyFromRoots(roots []uint32) []*big.Int {
	c := []*big.Int{big.NewInt(1)}
	for _, r := range roots {
		rs := poly.IndexToScalar(r)
		next := make([]*big.Int, len(c)+1)
		for i := range next {
			next[i] = big.NewInt(0)
		}
		for i := 0; i < len(c); i++ {
			next[i] = ecc.ScalarSub(next[i], ecc.ScalarMul(rs, c[i]))
			next[i+1] = ecc.ScalarAdd(next[i+1], c[i])
		}
		c = next
	}
	return c
}

// lagrangeNode0 is the Lagrange basis for node 0 over {0} ∪ honest:
// L0(0)=1, L0(j)=0 for every honest j.
func lagrangeNode0(honest []uint32) []*big.Int {
	num := polyFromRoots(honest)
	denom := big.NewInt(1)
	for _, j := range honest {
		denom = ecc.ScalarMul(denom, ecc.ScalarNeg(poly.IndexToScalar(j)))
	}
	inv, err := ecc.ScalarInvert(denom)
	if err != nil {
		panic(err)
	}
	out := make([]*big.Int, len(num))
	for i, c := range num {
		out[i] = ecc.ScalarMul(c, inv)
	}
	return out
}

// maliciousCanceller crafts a commitment whose constant term is w0*G - S*G (a
// point whose discrete log it does not know), then attaches its strongest
// available proof: a genuine PoP for w0*G (a point it controls), obtained from
// the real DkgRound1 API. That PoP is bound to a different commitment, so it
// cannot authenticate the crafted one.
func maliciousCanceller(idx uint32, threshold int, honestCommits []frost.DkgCommitPackage, honestIndices []uint32, w []*big.Int) (frost.DkgCommitPackage, []frost.DkgSharePackage) {
	// S*G = sum of honest constant commitments (a public point; S stays unknown).
	sg, err := ecc.LiftX(honestCommits[0].VssCommits[0][:])
	if err != nil {
		panic(err)
	}
	for _, c := range honestCommits[1:] {
		pt, err := ecc.LiftX(c.VssCommits[0][:])
		if err != nil {
			panic(err)
		}
		sg = ecc.PointAdd(sg, pt)
	}

	l0 := lagrangeNode0(honestIndices)
	vssCommits := make([][33]byte, len(w))
	for k := range w {
		term := ecc.ScalarBaseMulti(w[k]) // w[k]*G
		var l0k *big.Int
		if k < len(l0) {
			l0k = l0[k]
		} else {
			l0k = big.NewInt(0)
		}
		if l0k.Sign() != 0 {
			term = ecc.PointAdd(term, ecc.NegatePoint(ecc.ScalarMulti(sg, l0k)))
		}
		vssCommits[k] = ecc.SerializePoint(term)
	}

	// Strongest forgery the attacker can mount: a real proof for w0*G, which it
	// controls, generated through the honest API with the same index.
	wBytes := make([][32]byte, len(w))
	for i, c := range w {
		wBytes[i] = ecc.ScalarToBytes(c)
	}
	_, decoy := frost.DkgRound1(idx, threshold, wBytes)

	sharesOut := make([]frost.DkgSharePackage, len(honestIndices))
	for i, j := range honestIndices {
		sharesOut[i] = frost.DkgSharePackage{
			SenderIdx:    idx,
			RecipientIdx: j,
			Seckey:       ecc.ScalarToBytes(evalCoeffs(w, j)),
		}
	}

	return frost.DkgCommitPackage{Idx: idx, VssCommits: vssCommits, Pop: decoy.Pop}, sharesOut
}

func TestRogueCancellerRejected2Of2(t *testing.T) {
	threshold := 2
	l := repByte(0x00)
	l[31] = 0xbe
	l[30] = 0xef
	w := []*big.Int{
		ecc.ScalarFromBytes(l),
		ecc.ScalarFromBytes(repByte(0xc0)),
	}

	coeffs1, commit1 := frost.DkgRound1(1, threshold, [][32]byte{repByte(0xaa)})
	commit2, shares2 := maliciousCanceller(2, threshold, []frost.DkgCommitPackage{commit1}, []uint32{1}, w)
	all := []frost.DkgCommitPackage{commit1, commit2}

	// The crafted commitment's share still passes VSS — that was never the
	// defense. The PoP is what fails.
	ok, err := frost.VerifyDkgShare(&shares2[0], &commit2, threshold)
	if err != nil || !ok {
		t.Fatalf("expected crafted share to pass VSS, got ok=%v err=%v", ok, err)
	}
	popOK, err := frost.VerifyDkgPop(2, commit2.VssCommits[0], commit2.Pop)
	if err != nil {
		t.Fatal(err)
	}
	if popOK {
		t.Fatal("no valid PoP should exist for the crafted commitment")
	}

	_, err = frost.DkgFinalize(1, coeffs1, shares2, all, threshold)
	if err == nil {
		t.Fatal("finalize must reject the rogue commitment instead of folding l*G into the group key")
	}
}

func TestRogueCancellerRejected4Of5HonestMajority(t *testing.T) {
	// n = 5, t = 4: honest {1,2,3} (a 3/5 majority, below threshold 4),
	// malicious 4 (canceller) + 5 (filler).
	threshold := 4
	honest := []uint32{1, 2, 3}
	l := repByte(0x00)
	l[31] = 0x0d
	l[30] = 0xd0
	l[29] = 0xde
	l[28] = 0xc0
	k5 := repByte(0x00)
	k5[31] = 0x45
	w := []*big.Int{
		ecc.ScalarSub(ecc.ScalarFromBytes(l), ecc.ScalarFromBytes(k5)),
		ecc.ScalarFromBytes(repByte(0x11)),
		ecc.ScalarFromBytes(repByte(0x22)),
		ecc.ScalarFromBytes(repByte(0x33)),
	}

	hCoeffs := make([][][32]byte, len(honest))
	hCommits := make([]frost.DkgCommitPackage, len(honest))
	for i, idx := range honest {
		hCoeffs[i], hCommits[i] = frost.DkgRound1(idx, threshold, nil)
	}
	commit4, c4 := maliciousCanceller(4, threshold, hCommits, honest, w)
	coeffs5, commit5 := frost.DkgRound1(5, threshold, [][32]byte{k5})

	all := append(append([]frost.DkgCommitPackage{}, hCommits...), commit4, commit5)

	for slot, me := range honest {
		var received []frost.DkgSharePackage
		for s, sender := range honest {
			if sender != me {
				sp, err := frost.DkgRound2(sender, hCoeffs[s], me)
				if err != nil {
					t.Fatal(err)
				}
				received = append(received, sp)
			}
		}
		for _, sp := range c4 {
			if sp.RecipientIdx == me {
				received = append(received, sp)
			}
		}
		sp5, err := frost.DkgRound2(5, coeffs5, me)
		if err != nil {
			t.Fatal(err)
		}
		received = append(received, sp5)

		_, err = frost.DkgFinalize(me, hCoeffs[slot], received, all, threshold)
		if err == nil {
			t.Fatalf("honest party %d must reject the rogue DKG instead of accepting l*G", me)
		}
	}
}

func TestHonestDkgStillFinalizesAndPopRoundtrips(t *testing.T) {
	threshold := 2
	coeffs1, commit1 := frost.DkgRound1(1, threshold, [][32]byte{repByte(0xaa)})
	coeffs2, commit2 := frost.DkgRound1(2, threshold, [][32]byte{repByte(0xbb)})
	all := []frost.DkgCommitPackage{commit1, commit2}

	// Honest PoPs verify.
	for _, c := range all {
		ok, err := frost.VerifyDkgPop(c.Idx, c.VssCommits[0], c.Pop)
		if err != nil || !ok {
			t.Fatalf("honest PoP for %d must verify, got ok=%v err=%v", c.Idx, ok, err)
		}
	}

	// A PoP presented under the wrong index does not verify (binding).
	if ok, _ := frost.VerifyDkgPop(2, commit1.VssCommits[0], commit1.Pop); ok {
		t.Fatal("PoP must be bound to its index")
	}

	// A tampered PoP response does not verify.
	bad := commit1.Pop
	bad.Z[0] ^= 0xff
	if ok, _ := frost.VerifyDkgPop(1, commit1.VssCommits[0], bad); ok {
		t.Fatal("tampered PoP must not verify")
	}

	share21, err := frost.DkgRound2(2, coeffs2, 1)
	if err != nil {
		t.Fatal(err)
	}
	share12, err := frost.DkgRound2(1, coeffs1, 2)
	if err != nil {
		t.Fatal(err)
	}
	out1, err := frost.DkgFinalize(1, coeffs1, []frost.DkgSharePackage{share21}, all, threshold)
	if err != nil {
		t.Fatal(err)
	}
	out2, err := frost.DkgFinalize(2, coeffs2, []frost.DkgSharePackage{share12}, all, threshold)
	if err != nil {
		t.Fatal(err)
	}

	if out1.Group.GroupPk != out2.Group.GroupPk {
		t.Fatal("honest parties must agree on the group key")
	}

	for _, pair := range []struct {
		out frost.DkgOutput
		idx uint32
	}{{out1, 1}, {out2, 2}} {
		sp := frost.SharePackage{Idx: pair.idx, Seckey: pair.out.Share.Seckey}
		if !frost.IsGroupMember(&pair.out.Group, &sp) {
			t.Fatalf("IsGroupMember failed for %d", pair.idx)
		}
		secret := types.SecretShare{ID: pair.idx, Seckey: pair.out.Share.Seckey}
		ok, err := shares.VerifyShare(pair.out.VssCommits, &secret, threshold)
		if err != nil || !ok {
			t.Fatalf("verify_share failed for %d: ok=%v err=%v", pair.idx, ok, err)
		}
	}

	// Sanity: the group key is the honest sum of constant terms.
	c1, _ := ecc.LiftX(commit1.VssCommits[0][:])
	c2, _ := ecc.LiftX(commit2.VssCommits[0][:])
	expected := ecc.SerializePoint(ecc.PointAdd(c1, c2))
	if !bytes.Equal(out1.Group.GroupPk[:], expected[:]) {
		t.Fatal("group key must be the honest sum of constant commitments")
	}
	// And not under solo control via some l.
	l := repByte(0x00)
	l[31] = 0xef
	if out1.Group.GroupPk == helpers.GetPubkey(l) {
		t.Fatal("group key must not be attacker-chosen")
	}
}
