// Package frost provides high-level FROST threshold signing API.
package frost

import (
	"crypto/sha256"
	"encoding/binary"
	"slices"

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
	slices.Sort(sortedMembers)

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

// CreatePartialSigPackage produces a partial signature package.
func CreatePartialSigPackage(session *SignSession, share *SharePackage, secretNonce *SecretNoncePair) (PartialSigPackage, error) {
	lowShare := toSecretShare(share)
	lowSnonce := types.SecretNonce{
		ID:       share.Idx,
		BinderSn: secretNonce.BinderSn,
		HiddenSn: secretNonce.HiddenSn,
	}

	pnonces := toPublicNonces(session.Nonces)
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
	if len(pkg.Psigs) != len(session.Messages) {
		return "partial sig count does not match message count", nil
	}

	member := GetMemberByIdx(grp, pkg.Idx)
	if member == nil {
		return "member index not found in group", nil
	}
	if member.Pubkey != pkg.Pubkey {
		return "pubkey does not match member index", nil
	}

	memberInSession := false
	for _, idx := range session.Members {
		if idx == pkg.Idx {
			memberInSession = true
			break
		}
	}
	if !memberInSession {
		return "member is not in signing session", nil
	}

	pnonces := toPublicNonces(session.Nonces)
	var pnonce *MemberNonce
	for i := range session.Nonces {
		if session.Nonces[i].Idx == pkg.Idx {
			pnonce = &session.Nonces[i]
			break
		}
	}
	if pnonce == nil {
		return "no nonce for member", nil
	}
	lowPnonce := types.PublicNonce{ID: pnonce.Idx, BinderPn: pnonce.BinderPn, HiddenPn: pnonce.HiddenPn}

	for i, msg := range session.Messages {
		psigEntry := pkg.Psigs[i]

		tweaks := make([][32]byte, len(msg.Tweaks))
		copy(tweaks, msg.Tweaks)

		ctx, err := context.GetGroupSigningCtx(session.GroupPk[:], pnonces, msg.Message, tweaks)
		if err != nil {
			return "", err
		}

		ok, err := sign.VerifyPartialSig(&ctx, &lowPnonce, pkg.Pubkey, psigEntry.Psig)
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

	pnonces := toPublicNonces(session.Nonces)
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
