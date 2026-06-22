// Package sign provides signing and signature verification.
package sign

import (
	"bytes"
	"math/big"

	"github.com/frost-taproot/frost-taproot-go/commit"
	"github.com/frost-taproot/frost-taproot-go/ecc"
	"github.com/frost-taproot/frost-taproot-go/helpers"
	"github.com/frost-taproot/frost-taproot-go/poly"
	"github.com/frost-taproot/frost-taproot-go/types"
	"github.com/frost-taproot/frost-taproot-go/util"
)

// SignMsg produces a partial signature for a signing session.
func SignMsg(ctx *types.GroupSigningCtx, share *types.SecretShare, snonce *types.SecretNonce) (types.ShareSignature, error) {
	if snonce.ID != share.ID {
		return types.ShareSignature{}, &util.AssertionError{Message: "commit index does not match share index"}
	}

	bindFactorBytes, err := commit.GetBindFactor(ctx.BindFactors, share.ID)
	if err != nil {
		return types.ShareSignature{}, err
	}
	indexes := make([]*big.Int, len(ctx.Indexes))
	for i, idx := range ctx.Indexes {
		indexes[i] = poly.IndexToScalar(idx)
	}
	coefficient, err := poly.InterpolateX(indexes, poly.IndexToScalar(share.ID))
	if err != nil {
		return types.ShareSignature{}, err
	}

	rElem, err := ecc.LiftX(ctx.GroupPn[:])
	if err != nil {
		return types.ShareSignature{}, err
	}

	// The arithmetic below is constant time with respect to the secret share and
	// secret nonces: every step keeps a secret as the base operand and applies
	// only public values (parity, state, bind factor, challenge, lagrange
	// coefficient) as tweaks. A variable-time scalar mul/add here would leak the
	// share via the timing of /sign/complete.
	coeff := ecc.ScalarToBytes(coefficient)
	snonceH := snonce.HiddenSn
	snonceB := snonce.BinderSn
	if !ecc.HasEvenY(rElem) {
		snonceH = ecc.ScalarNegCT(snonceH)
		snonceB = ecc.ScalarNegCT(snonceB)
	}

	// sk = parity * state * seckey
	sk := ecc.ScalarMulCT(ecc.ScalarMulCT(share.Seckey, ctx.GroupPt.State), ctx.GroupPt.Parity)

	// nk = hidden_sn + binder_sn * bind_factor
	nk := ecc.ScalarAddCT(snonceH, ecc.ScalarMulCT(snonceB, bindFactorBytes))

	// ps = challenge * coefficient * sk + nk
	psk := ecc.ScalarMulCT(ecc.ScalarMulCT(sk, ctx.Challenge), coeff)
	ps := ecc.ScalarAddCT(psk, nk)

	return types.ShareSignature{
		ID:     share.ID,
		Psig:   ps,
		Pubkey: helpers.GetPubkey(share.Seckey),
	}, nil
}

// CombinePartialSigs aggregates partial signatures into a final BIP340 Schnorr signature.
func CombinePartialSigs(ctx *types.GroupSigningCtx, psigs []types.ShareSignature) ([64]byte, error) {
	commitPrefix := commit.GetGroupPrefix(ctx.Pnonces, ctx.GroupPk, ctx.Message)
	groupBinders := commit.GetGroupBinders(ctx.Pnonces, commitPrefix)
	groupPnonce, err := commit.GetGroupPubnonce(ctx.Pnonces, groupBinders)
	if err != nil {
		return [64]byte{}, err
	}

	// Sum all partial signatures
	ps := big.NewInt(0)
	for _, s := range psigs {
		ps = ecc.ScalarAdd(ps, ecc.ScalarFromBytes(s.Psig))
	}

	// twk = challenge * parity * tweak
	challenge := ecc.ScalarFromBytes(ctx.Challenge)
	parity := ecc.ScalarFromBytes(ctx.GroupPt.Parity)
	tweak := ecc.ScalarFromBytes(ctx.GroupPt.Tweak)
	twk := ecc.ScalarMul(ecc.ScalarMul(challenge, parity), tweak)
	s := ecc.ScalarAdd(ps, twk)

	// Signature = R_x (32 bytes) || s (32 bytes)
	var sig [64]byte
	copy(sig[:32], groupPnonce[1:])
	sBytes := ecc.ScalarToBytes(s)
	copy(sig[32:], sBytes[:])
	return sig, nil
}

// VerifyPartialSig verifies a partial signature from one participant.
func VerifyPartialSig(ctx *types.GroupSigningCtx, pnonce *types.PublicNonce, sharePk [33]byte, sharePsig [32]byte) (bool, error) {
	binderBytes, err := commit.GetBindFactor(ctx.BindFactors, pnonce.ID)
	if err != nil {
		return false, err
	}
	binder := ecc.ScalarFromBytes(binderBytes)

	hiddenElem, err := ecc.LiftX(pnonce.HiddenPn[:])
	if err != nil {
		return false, err
	}
	binderElem, err := ecc.LiftX(pnonce.BinderPn[:])
	if err != nil {
		return false, err
	}
	publicElem, err := ecc.LiftX(sharePk[:])
	if err != nil {
		return false, err
	}

	rElem, err := ecc.LiftX(ctx.GroupPn[:])
	if err != nil {
		return false, err
	}

	if !ecc.HasEvenY(rElem) {
		hiddenElem = ecc.NegatePoint(hiddenElem)
		binderElem = ecc.NegatePoint(binderElem)
	}

	commitElem := ecc.ScalarMulti(binderElem, binder)
	nonceElem, err := ecc.ElementAdd(hiddenElem, commitElem)
	if err != nil {
		return false, err
	}

	indexes := make([]*big.Int, len(ctx.Indexes))
	for i, idx := range ctx.Indexes {
		indexes[i] = poly.IndexToScalar(idx)
	}
	lambdaI, err := poly.InterpolateX(indexes, poly.IndexToScalar(pnonce.ID))
	if err != nil {
		return false, err
	}

	parity := ecc.ScalarFromBytes(ctx.GroupPt.Parity)
	state := ecc.ScalarFromBytes(ctx.GroupPt.State)
	chal := ecc.ScalarMul(ecc.ScalarMul(ecc.ScalarFromBytes(ctx.Challenge), lambdaI), ecc.ScalarMul(parity, state))

	sig := ecc.ScalarFromBytes(sharePsig)
	sg := ecc.ScalarBaseMulti(sig)
	pki := ecc.ScalarMulti(publicElem, chal)
	r, err := ecc.ElementAdd(nonceElem, pki)
	if err != nil {
		return false, err
	}

	return bytes.Equal(sg.X.Bytes(), r.X.Bytes()), nil
}

// VerifyFinalSig verifies a final aggregated BIP340 Schnorr signature.
func VerifyFinalSig(ctx *types.GroupKeyContext, message []byte, signature [64]byte) (bool, error) {
	// BIP340 verification
	// group_pk is 33-byte compressed; BIP340 uses x-only (32 bytes)
	pkBytes := ctx.GroupPk[1:]

	// Parse R from signature (first 32 bytes)
	rPoint, err := ecc.LiftX(signature[:32])
	if err != nil {
		return false, nil
	}

	// Parse s from signature (last 32 bytes)
	s := new(big.Int).SetBytes(signature[32:])

	// Parse public key
	pkPoint, err := ecc.LiftX(pkBytes)
	if err != nil {
		return false, nil
	}

	// Compute challenge
	challenge, err := helpers.GetChallenge(
		signature[:32],
		ctx.GroupPk[:],
		message,
	)
	if err != nil {
		return false, err
	}

	// Verify: s*G = R + challenge*P
	sG := ecc.ScalarBaseMulti(s)
	cP := ecc.ScalarMulti(pkPoint, challenge)
	rhs, err := ecc.ElementAdd(rPoint, cP)
	if err != nil {
		return false, err
	}

	return sG.X.Cmp(rhs.X) == 0 && sG.Y.Cmp(rhs.Y) == 0, nil
}
