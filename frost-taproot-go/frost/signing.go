// Package frost provides high-level FROST threshold signing API.
package frost

import (
	"crypto/sha256"
	"encoding/binary"

	"github.com/frost-taproot/frost-taproot-go/context"
	"github.com/frost-taproot/frost-taproot-go/helpers"
	"github.com/frost-taproot/frost-taproot-go/sign"
	"github.com/frost-taproot/frost-taproot-go/types"
	"github.com/frost-taproot/frost-taproot-go/util"
)

// CreateSignSession creates a signing session.
func CreateSignSession(grp *GroupPackage, members []uint32, messages []SignMessage, nonces []MemberNonce) (SignSession, error) {
	if len(nonces) != len(members) {
		return SignSession{}, &util.AssertionError{Message: "nonce count must equal member count"}
	}

	sortedMembers := make([]uint32, len(members))
	copy(sortedMembers, members)
	for i := 0; i < len(sortedMembers); i++ {
		for j := i + 1; j < len(sortedMembers); j++ {
			if sortedMembers[j] < sortedMembers[i] {
				sortedMembers[i], sortedMembers[j] = sortedMembers[j], sortedMembers[i]
			}
		}
	}

	sid := computeSessionId(grp, sortedMembers, messages)

	return SignSession{
		Sid:      sid,
		GroupPk:  grp.GroupPk,
		Members:  sortedMembers,
		Messages: messages,
		Nonces:   nonces,
	}, nil
}

func computeSessionId(grp *GroupPackage, members []uint32, messages []SignMessage) [32]byte {
	gid := GetGroupId(grp)
	h := sha256.New()
	h.Write(gid[:])
	for _, m := range members {
		buf := make([]byte, 4)
		binary.BigEndian.PutUint32(buf, m)
		h.Write(buf)
	}
	for _, msg := range messages {
		buf := make([]byte, 4)
		binary.BigEndian.PutUint32(buf, uint32(len(msg.Message)))
		h.Write(buf)
		h.Write(msg.Message)
		for _, t := range msg.Tweaks {
			h.Write(t[:])
		}
	}
	var out [32]byte
	h.Sum(out[:0])
	return out
}

func buildPublicNonces(nonces []MemberNonce) []types.PublicNonce {
	pnonces := make([]types.PublicNonce, len(nonces))
	for i, n := range nonces {
		pnonces[i] = types.PublicNonce{
			ID:       n.Idx,
			BinderPn: n.BinderPn,
			HiddenPn: n.HiddenPn,
		}
	}
	return pnonces
}

// CreatePartialSigPackage produces a partial signature package.
func CreatePartialSigPackage(session *SignSession, share *SharePackage, secretNonce *SecretNoncePair) (PartialSigPackage, error) {
	lowShare := types.SecretShare{
		ID:     share.Idx,
		Seckey: share.Seckey,
	}
	lowSnonce := types.SecretNonce{
		ID:       share.Idx,
		BinderSn: secretNonce.BinderSn,
		HiddenSn: secretNonce.HiddenSn,
	}

	pnonces := buildPublicNonces(session.Nonces)
	psigs := make([]PartialSig, len(session.Messages))

	for i, msg := range session.Messages {
		tweaks := make([][32]byte, len(msg.Tweaks))
		copy(tweaks, msg.Tweaks)

		ctx, err := context.GetGroupSigningCtx(session.GroupPk[:], pnonces, msg.Message, tweaks)
		if err != nil {
			return PartialSigPackage{}, err
		}

		sig, err := sign.SignMsg(&ctx, &lowShare, &lowSnonce)
		if err != nil {
			return PartialSigPackage{}, err
		}

		psigs[i] = PartialSig{
			Message: msg.Message,
			Psig:    sig.Psig,
		}
	}

	pubkey := helpers.GetPubkey(share.Seckey)

	return PartialSigPackage{
		Idx:    share.Idx,
		Pubkey: pubkey,
		Sid:    session.Sid,
		Psigs:  psigs,
	}, nil
}

// VerifyPartialSigPackage verifies a partial signature package.
func VerifyPartialSigPackage(session *SignSession, grp *GroupPackage, pkg *PartialSigPackage) (string, error) {
	if pkg.Sid != session.Sid {
		return "session id mismatch", nil
	}

	memberPubkeys := make([][33]byte, len(grp.Members))
	for i, m := range grp.Members {
		memberPubkeys[i] = m.Pubkey
	}

	found := false
	for _, pk := range memberPubkeys {
		if pk == pkg.Pubkey {
			found = true
			break
		}
	}
	if !found {
		return "pubkey not found in group", nil
	}

	pnonces := buildPublicNonces(session.Nonces)
	var pnonce *types.PublicNonce
	for i := range pnonces {
		if pnonces[i].ID == pkg.Idx {
			pnonce = &pnonces[i]
			break
		}
	}
	if pnonce == nil {
		return "no nonce for member", nil
	}

	for i, msg := range session.Messages {
		psigEntry := pkg.Psigs[i]

		tweaks := make([][32]byte, len(msg.Tweaks))
		copy(tweaks, msg.Tweaks)

		ctx, err := context.GetGroupSigningCtx(session.GroupPk[:], pnonces, msg.Message, tweaks)
		if err != nil {
			return "", err
		}

		ok, err := sign.VerifyPartialSig(&ctx, pnonce, pkg.Pubkey, psigEntry.Psig)
		if err != nil {
			return "", err
		}
		if !ok {
			return "partial sig invalid", nil
		}
	}

	return "", nil
}

// CombineSignatures combines partial signature packages into final signatures.
func CombineSignatures(session *SignSession, grp *GroupPackage, pkgs []PartialSigPackage) ([]Signature, error) {
	if len(pkgs) < grp.Threshold {
		return nil, &util.AssertionError{Message: "not enough partial sigs"}
	}

	pnonces := buildPublicNonces(session.Nonces)
	signatures := make([]Signature, len(session.Messages))

	for i, msg := range session.Messages {
		tweaks := make([][32]byte, len(msg.Tweaks))
		copy(tweaks, msg.Tweaks)

		ctx, err := context.GetGroupSigningCtx(session.GroupPk[:], pnonces, msg.Message, tweaks)
		if err != nil {
			return nil, err
		}

		shareSigs := make([]types.ShareSignature, len(pkgs))
		for j, pkg := range pkgs {
			if i >= len(pkg.Psigs) {
				return nil, &util.AssertionError{Message: "missing psig in package"}
			}
			shareSigs[j] = types.ShareSignature{
				ID:     pkg.Idx,
				Pubkey: pkg.Pubkey,
				Psig:   pkg.Psigs[i].Psig,
			}
		}

		sig, err := sign.CombinePartialSigs(&ctx, shareSigs)
		if err != nil {
			return nil, err
		}

		keyCtx := ctx.KeyContext()
		ok, err := sign.VerifyFinalSig(&keyCtx, msg.Message, sig)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, &util.AssertionError{Message: "combined signature failed verification"}
		}

		signatures[i] = Signature{
			Message: msg.Message,
			Pubkey:  ctx.GroupPk,
			Sig:     sig,
		}
	}

	return signatures, nil
}
