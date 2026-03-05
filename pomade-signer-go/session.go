package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"math/big"

	"github.com/frost-taproot/frost-taproot-go/context"
	"github.com/frost-taproot/frost-taproot-go/ecdh"
	"github.com/frost-taproot/frost-taproot-go/helpers"
	"github.com/frost-taproot/frost-taproot-go/sign"
	"github.com/frost-taproot/frost-taproot-go/types"
)

type sighashCtx struct {
	sighash [32]byte
	ctx     types.GroupSigningCtx
}

func decodeHex32(s string) ([32]byte, bool) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return [32]byte{}, false
	}
	var out [32]byte
	copy(out[:], b)
	return out, true
}

func decodeHex33(s string) ([33]byte, bool) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 33 {
		return [33]byte{}, false
	}
	var out [33]byte
	copy(out[:], b)
	return out, true
}

func isGroupMember(group Group, share Share) bool {
	seckey, ok := decodeHex32(share.Seckey)
	if !ok {
		return false
	}
	pubkey := helpers.GetPubkey(seckey)
	pubkeyHex := hex.EncodeToString(pubkey[:])
	for _, c := range group.Commits {
		if c.Idx == share.Idx && c.Pubkey == pubkeyHex {
			return true
		}
	}
	return false
}

func computeGroupID(group Group) [32]byte {
	commits := append([]Commit(nil), group.Commits...)
	for i := 0; i < len(commits); i++ {
		for j := i + 1; j < len(commits); j++ {
			if commits[j].Idx < commits[i].Idx {
				commits[i], commits[j] = commits[j], commits[i]
			}
		}
	}
	h := sha256.New()
	for _, c := range commits {
		idx := make([]byte, 32)
		binary.BigEndian.PutUint32(idx[28:], c.Idx)
		h.Write(idx)
		if b, err := hex.DecodeString(c.HiddenPn); err == nil {
			h.Write(b)
		}
		if b, err := hex.DecodeString(c.BinderPn); err == nil {
			h.Write(b)
		}
	}
	if b, err := hex.DecodeString(group.GroupPk); err == nil {
		h.Write(b)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func numToBytesVarWidth(n uint32) []byte {
	if n <= 0xFF {
		return []byte{byte(n)}
	}
	if n <= 0xFFFF {
		out := make([]byte, 2)
		binary.BigEndian.PutUint16(out, uint16(n))
		return out
	}
	out := make([]byte, 4)
	binary.BigEndian.PutUint32(out, n)
	return out
}

func computeSessionID(group Group, request SignRequestInner) [32]byte {
	gid := computeGroupID(group)
	h := sha256.New()
	h.Write(gid[:])
	for _, m := range request.Members {
		h.Write(numToBytesVarWidth(m))
	}
	for _, sigvec := range request.Hashes {
		for _, hh := range sigvec {
			if b, err := hex.DecodeString(hh); err == nil {
				h.Write(b)
			}
		}
	}
	if request.Content == nil {
		h.Write([]byte{0x00})
	} else if b, err := hex.DecodeString(*request.Content); err == nil {
		h.Write(b)
	}
	h.Write([]byte(request.Type))
	stamp := make([]byte, 4)
	binary.BigEndian.PutUint32(stamp, uint32(request.Stamp))
	h.Write(stamp)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func getSighashBinder(sessionID [32]byte, memberIdx uint32, sigvec []string) [32]byte {
	h := sha256.New()
	h.Write(sessionID[:])
	idx := make([]byte, 4)
	binary.BigEndian.PutUint32(idx, memberIdx)
	h.Write(idx)
	for _, hh := range sigvec {
		if b, err := hex.DecodeString(hh); err == nil {
			h.Write(b)
		}
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func tweakCommitPnonces(commit Commit, sessionID [32]byte, sigvec []string) (types.PublicNonce, bool) {
	binder := getSighashBinder(sessionID, commit.Idx, sigvec)
	hidden := mustDecode33(commit.HiddenPn)
	hiddenPn, err := helpers.TweakPubkey(hidden[:], binder)
	if err != nil {
		return types.PublicNonce{}, false
	}
	binderPoint := mustDecode33(commit.BinderPn)
	binderPn, err := helpers.TweakPubkey(binderPoint[:], binder)
	if err != nil {
		return types.PublicNonce{}, false
	}
	return types.PublicNonce{ID: commit.Idx, HiddenPn: hiddenPn, BinderPn: binderPn}, true
}

func tweakShareSnonces(share Share, sessionID [32]byte, sigvec []string) (types.SecretNonce, bool) {
	binder := getSighashBinder(sessionID, share.Idx, sigvec)
	hiddenSn := helpers.TweakSeckey(mustDecode32(share.HiddenSn), binder)
	binderSn := helpers.TweakSeckey(mustDecode32(share.BinderSn), binder)
	return types.SecretNonce{ID: share.Idx, HiddenSn: hiddenSn, BinderSn: binderSn}, true
}

func mustDecode32(s string) [32]byte {
	b, _ := decodeHex32(s)
	return b
}

func mustDecode33(s string) [33]byte {
	b, _ := decodeHex33(s)
	return b
}

func buildSighashContexts(group Group, request SignRequestInner, sessionID [32]byte) ([]sighashCtx, bool) {
	groupPk, ok := decodeHex33(group.GroupPk)
	if !ok {
		return nil, false
	}
	if len(request.Hashes) == 0 {
		return nil, false
	}
	out := make([]sighashCtx, 0, len(request.Hashes))
	for _, sigvec := range request.Hashes {
		if len(sigvec) == 0 {
			return nil, false
		}
		sighash, ok := decodeHex32(sigvec[0])
		if !ok {
			return nil, false
		}
		tweaks := make([][32]byte, 0, len(sigvec)-1)
		for _, tw := range sigvec[1:] {
			if b, ok := decodeHex32(tw); ok {
				tweaks = append(tweaks, b)
			}
		}
		pnonces := make([]types.PublicNonce, 0, len(request.Members))
		for _, id := range request.Members {
			for _, c := range group.Commits {
				if c.Idx != id {
					continue
				}
				if nonce, ok := tweakCommitPnonces(c, sessionID, sigvec); ok {
					pnonces = append(pnonces, nonce)
				}
			}
		}
		ctx, err := context.GetGroupSigningCtx(groupPk[:], pnonces, sighash[:], tweaks)
		if err != nil {
			return nil, false
		}
		out = append(out, sighashCtx{sighash: sighash, ctx: ctx})
	}
	return out, true
}

func verifySessionPkg(group Group, request SignRequestInner) bool {
	gid := computeGroupID(group)
	sid := computeSessionID(group, request)
	return hex.EncodeToString(gid[:]) == request.Gid && hex.EncodeToString(sid[:]) == request.Sid
}

func createPsigPkg(group Group, request SignRequest, share Share) (*SignResult, bool) {
	sessionID := computeSessionID(group, request.Request)
	contexts, ok := buildSighashContexts(group, request.Request, sessionID)
	if !ok {
		return nil, false
	}
	seckey, ok := decodeHex32(share.Seckey)
	if !ok {
		return nil, false
	}
	secretShare := types.SecretShare{ID: share.Idx, Seckey: seckey}
	psigs := make([][2]string, 0, len(contexts))
	for _, sc := range contexts {
		sighashHex := hex.EncodeToString(sc.sighash[:])
		var sigvec []string
		for _, candidate := range request.Request.Hashes {
			if len(candidate) > 0 && candidate[0] == sighashHex {
				sigvec = candidate
				break
			}
		}
		snonce, _ := tweakShareSnonces(share, sessionID, sigvec)
		sig, err := sign.SignMsg(&sc.ctx, &secretShare, &snonce)
		if err != nil {
			return nil, false
		}
		psigs = append(psigs, [2]string{sighashHex, hex.EncodeToString(sig.Psig[:])})
	}
	pubkey := helpers.GetPubkey(seckey)
	return &SignResult{
		Idx:    share.Idx,
		Psigs:  psigs,
		Pubkey: hex.EncodeToString(pubkey[:]),
		Sid:    hex.EncodeToString(sessionID[:]),
	}, true
}

// secp256k1 field prime P and generator x-coordinate.
var secp256k1P, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
var secp256k1Gx, _ = new(big.Int).SetString("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16)

func createEcdhPkg(request EcdhRequest, share Share) (*EcdhResult, bool) {
	ecdhPk, ok := decodeHex32(request.EcdhPk)
	if !ok {
		return nil, false
	}
	// Reject x-coordinates that are not in the canonical range [1, P-1].
	// Values >= P would be silently reduced mod P by LiftX, potentially
	// mapping attacker-controlled bytes onto valid curve points.
	x := new(big.Int).SetBytes(ecdhPk[:])
	if x.Sign() == 0 || x.Cmp(secp256k1P) >= 0 {
		return nil, false
	}
	// Reject the generator point G; its x-coordinate lifted with even Y gives G,
	// and multiplying by the secret share reveals the share itself.
	if x.Cmp(secp256k1Gx) == 0 {
		return nil, false
	}
	seckey, ok := decodeHex32(share.Seckey)
	if !ok {
		return nil, false
	}
	secretShare := types.SecretShare{ID: share.Idx, Seckey: seckey}
	ecdhShare, err := ecdh.CreateEcdhShare(request.Members, &secretShare, ecdhPk[:])
	if err != nil {
		return nil, false
	}
	return &EcdhResult{
		Idx:      ecdhShare.ID,
		Keyshare: hex.EncodeToString(ecdhShare.Pubkey[:]),
		Members:  request.Members,
		EcdhPk:   request.EcdhPk,
	}, true
}
