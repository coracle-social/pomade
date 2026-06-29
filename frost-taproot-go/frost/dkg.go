// Package frost provides high-level FROST threshold signing API.
package frost

import (
	"crypto/sha256"
	"encoding/binary"
	"math/big"
	"slices"

	"github.com/frost-taproot/frost-taproot-go/ecc"
	"github.com/frost-taproot/frost-taproot-go/poly"
	"github.com/frost-taproot/frost-taproot-go/shares"
	"github.com/frost-taproot/frost-taproot-go/types"
	"github.com/frost-taproot/frost-taproot-go/util"
	"github.com/frost-taproot/frost-taproot-go/vss"
)

// Domain separation tags for the DKG proof of possession.
var (
	dkgPopChallengeDST = []byte("frost-taproot/dkg-pop/challenge/v1")
	dkgPopNonceDST     = []byte("frost-taproot/dkg-pop/nonce/v1")
)

// dkgPopChallenge computes e = H(DST || idx || C0 || R) mod N. Binding the index
// and the commitment ties each proof to its participant and its commitment, so a
// proof cannot be replayed for a different index or commitment.
func dkgPopChallenge(idx uint32, c0 [33]byte, r [33]byte) *big.Int {
	h := sha256.New()
	h.Write(dkgPopChallengeDST)
	var idxBuf [4]byte
	binary.BigEndian.PutUint32(idxBuf[:], idx)
	h.Write(idxBuf[:])
	h.Write(c0[:])
	h.Write(r[:])
	var digest [32]byte
	h.Sum(digest[:0])
	return ecc.ScalarFromBytes(digest)
}

// createDkgPop builds a Schnorr proof of possession of a0 where C0 = a0*G.
//
// Uses a deterministic, secret-dependent nonce so Round 1 stays reproducible and
// never depends on an RNG for this step.
func createDkgPop(idx uint32, a0 *big.Int, c0 [33]byte) DkgPop {
	// Deterministic nonce k = H(DST || a0 || idx) mod N. Secret-derived, so it is
	// unpredictable to anyone who does not know a0.
	a0Bytes := ecc.ScalarToBytes(a0)
	h := sha256.New()
	h.Write(dkgPopNonceDST)
	h.Write(a0Bytes[:])
	var idxBuf [4]byte
	binary.BigEndian.PutUint32(idxBuf[:], idx)
	h.Write(idxBuf[:])
	var nonceDigest [32]byte
	h.Sum(nonceDigest[:0])
	k := ecc.ScalarFromBytes(nonceDigest)
	if k.Sign() == 0 {
		k = big.NewInt(1)
	}

	// R = k*G via the constant-time path (k is secret-derived).
	r := ecc.ScalarBaseMultiCT(ecc.ScalarToBytes(k))
	e := dkgPopChallenge(idx, c0, r)
	z := ecc.ScalarAdd(k, ecc.ScalarMul(e, a0))

	return DkgPop{R: r, Z: ecc.ScalarToBytes(z)}
}

// VerifyDkgPop verifies a proof of possession against C0 = VssCommits[0].
//
// Checks z*G == R + e*C0. Returns false when the proof does not verify (e.g. a
// crafted commitment whose discrete log the author does not know), and an error
// only on a point-decoding failure.
func VerifyDkgPop(idx uint32, c0 [33]byte, pop DkgPop) (bool, error) {
	rPoint, err := ecc.LiftX(pop.R[:])
	if err != nil {
		return false, err
	}
	c0Point, err := ecc.LiftX(c0[:])
	if err != nil {
		return false, err
	}
	e := dkgPopChallenge(idx, c0, pop.R)
	z := ecc.ScalarFromBytes(pop.Z)

	// All inputs here are public, so variable-time multiplication is fine.
	lhs := ecc.ScalarBaseMulti(z)
	rhs := ecc.PointAdd(rPoint, ecc.ScalarMulti(c0Point, e))
	return ecc.SerializePoint(lhs) == ecc.SerializePoint(rhs), nil
}

// DkgRound1 generates Round 1 polynomial and commitments.
func DkgRound1(idx uint32, threshold int, secrets [][32]byte) ([][32]byte, DkgCommitPackage) {
	coeffs := vss.CreateShareCoeffs(secrets, threshold)
	vssCommits := vss.GetShareCommits(coeffs)

	// Prove possession of the constant-term secret a_i0 behind VssCommits[0].
	// This is what later lets every participant reject a rogue commitment whose
	// discrete log its author does not actually know.
	pop := createDkgPop(idx, coeffs[0], vssCommits[0])

	secretCoeffs := make([][32]byte, len(coeffs))
	for i, c := range coeffs {
		secretCoeffs[i] = ecc.ScalarToBytes(c)
	}

	return secretCoeffs, DkgCommitPackage{Idx: idx, VssCommits: vssCommits, Pop: pop}
}

// DkgRound2 generates the private share for one recipient.
func DkgRound2(senderIdx uint32, secretCoeffs [][32]byte, recipientIdx uint32) (DkgSharePackage, error) {
	coeffs := make([]*big.Int, len(secretCoeffs))
	for i, c := range secretCoeffs {
		coeffs[i] = ecc.ScalarFromBytes(c)
	}
	x := poly.IndexToScalar(recipientIdx)
	shareScalar, err := poly.EvaluateX(coeffs, x)
	if err != nil {
		return DkgSharePackage{}, err
	}

	seckeyBytes := ecc.ScalarToBytes(shareScalar)

	return DkgSharePackage{
		SenderIdx:    senderIdx,
		RecipientIdx: recipientIdx,
		Seckey:       seckeyBytes,
	}, nil
}

// VerifyDkgShare verifies a share against sender's VSS commitments.
func VerifyDkgShare(share *DkgSharePackage, senderCommits *DkgCommitPackage, threshold int) (bool, error) {
	lowShare := types.SecretShare{
		ID:     share.RecipientIdx,
		Seckey: share.Seckey,
	}
	return shares.VerifyShare(senderCommits.VssCommits, &lowShare, threshold)
}

// DkgFinalize finalizes DKG and derives the group key.
func DkgFinalize(myIdx uint32, myCoeffs [][32]byte, received []DkgSharePackage, allCommits []DkgCommitPackage, threshold int) (DkgOutput, error) {
	// Verify every participant's proof of possession before trusting any of their
	// commitments. This closes the rogue-key attack: a participant broadcasting
	// last cannot fold a crafted VssCommits[0] (chosen to cancel the honest
	// contributions and steer the group key) into the sum, because it cannot
	// produce a valid PoP for a point whose discrete log it does not know.
	for i := range allCommits {
		c := &allCommits[i]
		if len(c.VssCommits) == 0 {
			return DkgOutput{}, &util.AssertionError{Message: "participant has no VSS commits"}
		}
		ok, err := VerifyDkgPop(c.Idx, c.VssCommits[0], c.Pop)
		if err != nil {
			return DkgOutput{}, err
		}
		if !ok {
			return DkgOutput{}, &util.AssertionError{Message: "DKG proof of possession failed"}
		}
	}

	// Validate all received shares
	for _, pkg := range received {
		var senderCommits *DkgCommitPackage
		for i := range allCommits {
			if allCommits[i].Idx == pkg.SenderIdx {
				senderCommits = &allCommits[i]
				break
			}
		}
		if senderCommits == nil {
			return DkgOutput{}, &util.RecordNotFoundError{Idx: pkg.SenderIdx}
		}
		ok, err := VerifyDkgShare(&pkg, senderCommits, threshold)
		if err != nil {
			return DkgOutput{}, err
		}
		if !ok {
			return DkgOutput{}, &util.AssertionError{Message: "DKG share failed VSS verification"}
		}
	}

	// Compute own share
	ownSharePkg, err := DkgRound2(myIdx, myCoeffs, myIdx)
	if err != nil {
		return DkgOutput{}, err
	}
	ownShare := types.SecretShare{
		ID:     myIdx,
		Seckey: ownSharePkg.Seckey,
	}

	// Aggregate shares
	allShares := make([]types.SecretShare, 0, len(received)+1)
	allShares = append(allShares, ownShare)
	for _, pkg := range received {
		allShares = append(allShares, types.SecretShare{
			ID:     myIdx,
			Seckey: pkg.Seckey,
		})
	}
	aggregate, err := shares.CombineSet(allShares)
	if err != nil {
		return DkgOutput{}, err
	}

	// Sort commits by idx
	sortedCommits := make([]DkgCommitPackage, len(allCommits))
	copy(sortedCommits, allCommits)
	slices.SortFunc(sortedCommits, func(a, b DkgCommitPackage) int {
		if a.Idx < b.Idx {
			return -1
		}
		if a.Idx > b.Idx {
			return 1
		}
		return 0
	})

	// Derive group public key
	firstCommits := make([][33]byte, len(sortedCommits))
	for i, c := range sortedCommits {
		firstCommits[i] = c.VssCommits[0]
	}
	groupPk, err := sumPoints(firstCommits)
	if err != nil {
		return DkgOutput{}, err
	}

	// Merge VSS commits
	var groupVssCommits [][33]byte
	for _, c := range sortedCommits {
		if groupVssCommits == nil {
			groupVssCommits = c.VssCommits
		} else {
			groupVssCommits, err = vss.MergeShareCommits(groupVssCommits, c.VssCommits)
			if err != nil {
				return DkgOutput{}, err
			}
		}
	}

	// Build member packages
	members := make([]MemberPackage, len(sortedCommits))
	for i, c := range sortedCommits {
		sharePubkey, err := evalVssPubkey(groupVssCommits, c.Idx)
		if err != nil {
			return DkgOutput{}, err
		}
		members[i] = MemberPackage{
			Idx:        c.Idx,
			Pubkey:     sharePubkey,
			IdentityPk: &c.VssCommits[0],
		}
	}

	grp := GroupPackage{
		GroupPk:   groupPk,
		Threshold: threshold,
		Members:   members,
	}

	return DkgOutput{
		Share: SharePackage{
			Idx:    myIdx,
			Seckey: aggregate.Seckey,
		},
		Group:      grp,
		VssCommits: groupVssCommits,
	}, nil
}

func sumPoints(points [][33]byte) ([33]byte, error) {
	if len(points) == 0 {
		return [33]byte{}, &util.AssertionError{Message: "cannot sum empty point list"}
	}
	acc, err := ecc.LiftX(points[0][:])
	if err != nil {
		return [33]byte{}, err
	}
	for _, p := range points[1:] {
		pt, err := ecc.LiftX(p[:])
		if err != nil {
			return [33]byte{}, err
		}
		acc = ecc.PointAdd(acc, pt)
	}
	return ecc.SerializePoint(acc), nil
}

func evalVssPubkey(commits [][33]byte, idx uint32) ([33]byte, error) {
	if len(commits) == 0 {
		return [33]byte{}, &util.AssertionError{Message: "no VSS commits"}
	}
	var acc *ecc.Point
	for k, commit := range commits {
		point, err := ecc.LiftX(commit[:])
		if err != nil {
			return [33]byte{}, err
		}
		exp := ecc.PowN(uint64(idx), uint64(k))
		term := ecc.ScalarMulti(point, exp)
		if acc == nil {
			acc = term
		} else {
			acc = ecc.PointAdd(acc, term)
		}
	}
	return ecc.SerializePoint(acc), nil
}
