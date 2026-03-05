// Package context provides signing context creation.
package context

import (
	"math/big"

	"github.com/frost-taproot/frost-taproot-go/commit"
	"github.com/frost-taproot/frost-taproot-go/ecc"
	"github.com/frost-taproot/frost-taproot-go/helpers"
	"github.com/frost-taproot/frost-taproot-go/types"
)

// GetPointState computes the accumulative parity state for a point with tweaks.
func GetPointState(element *ecc.Point, tweaks [][32]byte) (types.PointState, error) {
	pos := big.NewInt(1)
	neg := ecc.ScalarNeg(big.NewInt(1))

	point := &ecc.Point{X: new(big.Int).Set(element.X), Y: new(big.Int).Set(element.Y)}
	var parity *big.Int
	state := pos
	tweak := big.NewInt(0)

	for _, tBytes := range tweaks {
		t := ecc.ScalarFromBytes(tBytes)
		tg := ecc.ScalarBaseMulti(t)

		if ecc.HasEvenY(point) {
			parity = pos
		} else {
			parity = neg
		}

		if parity.Cmp(neg) == 0 {
			point = ecc.NegatePoint(point)
		}

		var err error
		point, err = ecc.ElementAdd(point, tg)
		if err != nil {
			return types.PointState{}, err
		}

		state = ecc.ScalarMul(state, parity)
		tweak = ecc.ModN(new(big.Int).Add(t, ecc.ScalarMul(parity, tweak)))
	}

	if ecc.HasEvenY(point) {
		parity = pos
	} else {
		parity = neg
	}

	return types.PointState{
		Parity: ecc.ScalarToBytes(parity),
		Point:  ecc.SerializePoint(point),
		State:  ecc.ScalarToBytes(state),
		Tweak:  ecc.ScalarToBytes(tweak),
	}, nil
}

// GetGroupKeyContext builds the group key context with optional tweaks.
func GetGroupKeyContext(pubkey []byte, tweaks [][32]byte) (types.GroupKeyContext, error) {
	intPt, err := ecc.LiftX(pubkey)
	if err != nil {
		return types.GroupKeyContext{}, err
	}
	intPkBytes := ecc.SerializePoint(intPt)

	groupPt, err := GetPointState(intPt, tweaks)
	if err != nil {
		return types.GroupKeyContext{}, err
	}

	return types.GroupKeyContext{
		GroupPt: groupPt,
		GroupPk: groupPt.Point,
		IntPt:   &intPkBytes,
		IntPk:   &intPkBytes,
		Tweak:   nil,
	}, nil
}

// GetGroupCommitContext builds the commit context from nonces and message.
func GetGroupCommitContext(keyCtx *types.GroupKeyContext, pnonces []types.PublicNonce, message []byte) (types.GroupCommitContext, error) {
	bindPrefix := commit.GetGroupPrefix(pnonces, keyCtx.GroupPk, message)
	bindFactors := commit.GetGroupBinders(pnonces, bindPrefix)
	groupPn, err := commit.GetGroupPubnonce(pnonces, bindFactors)
	if err != nil {
		return types.GroupCommitContext{}, err
	}
	indexes := commit.GetNonceIDs(pnonces)

	challenge, err := helpers.GetChallenge(groupPn[:], keyCtx.GroupPk[:], message)
	if err != nil {
		return types.GroupCommitContext{}, err
	}

	return types.GroupCommitContext{
		BindFactors: bindFactors,
		BindPrefix:  bindPrefix,
		Challenge:   ecc.ScalarToBytes(challenge),
		GroupPn:     groupPn,
		Indexes:     indexes,
		Message:     append([]byte(nil), message...),
		Pnonces:     append([]types.PublicNonce(nil), pnonces...),
	}, nil
}

// GetGroupSigningCtx builds the full signing context.
func GetGroupSigningCtx(groupPk []byte, pnonces []types.PublicNonce, message []byte, tweaks [][32]byte) (types.GroupSigningCtx, error) {
	keyCtx, err := GetGroupKeyContext(groupPk, tweaks)
	if err != nil {
		return types.GroupSigningCtx{}, err
	}

	comCtx, err := GetGroupCommitContext(&keyCtx, pnonces, message)
	if err != nil {
		return types.GroupSigningCtx{}, err
	}

	return types.GroupSigningCtx{
		GroupPt:     keyCtx.GroupPt,
		GroupPk:     keyCtx.GroupPk,
		IntPt:       keyCtx.IntPt,
		IntPk:       keyCtx.IntPk,
		Tweak:       keyCtx.Tweak,
		BindFactors: comCtx.BindFactors,
		BindPrefix:  comCtx.BindPrefix,
		Challenge:   comCtx.Challenge,
		GroupPn:     comCtx.GroupPn,
		Indexes:     comCtx.Indexes,
		Message:     comCtx.Message,
		Pnonces:     comCtx.Pnonces,
	}, nil
}
