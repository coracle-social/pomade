package integration

import (
	"bytes"
	"testing"

	"github.com/frost-taproot/frost-taproot-go/ecc"
	"github.com/frost-taproot/frost-taproot-go/frost"
	"github.com/frost-taproot/frost-taproot-go/helpers"
	"github.com/frost-taproot/frost-taproot-go/shares"
	"github.com/frost-taproot/frost-taproot-go/types"
)

// TestDealerFullFlow tests the complete dealer flow.
func TestDealerFullFlow(t *testing.T) {
	// 1. Trusted dealer generates a 2-of-3 group
	secrets := [][32]byte{
		mustHexTo32("0070ca75929ca1ec4cd70ac34f46079bdfdd87f9d0c0bf4275f3882f7b462d0f"),
		mustHexTo32("0e0376a7180253cdb8b6020bff0eda529760da65e715663e2152e4be2fc7b443"),
	}

	pkg, err := frost.GenerateDealerPackage(2, 3, secrets)
	if err != nil {
		t.Fatalf("GenerateDealerPackage failed: %v", err)
	}

	if pkg.Group.Threshold != 2 {
		t.Errorf("expected threshold 2, got %d", pkg.Group.Threshold)
	}
	if len(pkg.Shares) != 3 {
		t.Errorf("expected 3 shares, got %d", len(pkg.Shares))
	}
	for _, m := range pkg.Group.Members {
		if m.IdentityPk != nil {
			t.Error("expected nil identity_pk in dealer model")
		}
	}

	// 2. All three 2-of-3 subsets can sign
	message := []byte("hello from the dealer flow")

	subsets := [][2]int{{0, 1}, {0, 2}, {1, 2}}
	for _, subset := range subsets {
		sigs := signMessage(t, &pkg.Group, pkg.Shares, subset, message, nil)
		if len(sigs) != 1 {
			t.Fatalf("expected 1 signature, got %d", len(sigs))
		}
		if !bytes.Equal(sigs[0].Message, message) {
			t.Error("message mismatch in signature")
		}
		if !bytes.Equal(sigs[0].Pubkey[:], pkg.Group.GroupPk[:]) {
			t.Error("untweaked sig pubkey should equal group_pk")
		}
	}

	// 3. Tweaked signing produces a different pubkey
	tweak := mustHexTo32("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	tweakedSigs := signMessage(t, &pkg.Group, pkg.Shares, [2]int{0, 1}, message, [][32]byte{tweak})
	if len(tweakedSigs) != 1 {
		t.Fatalf("expected 1 tweaked signature, got %d", len(tweakedSigs))
	}
	if bytes.Equal(tweakedSigs[0].Pubkey[:], pkg.Group.GroupPk[:]) {
		t.Error("tweaked sig pubkey should differ from group_pk")
	}

	// 4. Threshold ECDH derives the same shared secret as direct scalar mult
	extSeckey := mustHexTo32("1111111111111111111111111111111111111111111111111111111111111111")
	extPubkey := helpers.GetPubkey(extSeckey)

	ecdhMembers := []uint32{1, 3}
	ecdh1, err := frost.CreateEcdhPkg(ecdhMembers, extPubkey, &pkg.Shares[0])
	if err != nil {
		t.Fatalf("CreateEcdhPkg failed for share 0: %v", err)
	}
	ecdh3, err := frost.CreateEcdhPkg(ecdhMembers, extPubkey, &pkg.Shares[2])
	if err != nil {
		t.Fatalf("CreateEcdhPkg failed for share 2: %v", err)
	}
	frostShared, err := frost.CombineEcdhPkgs([]frost.EcdhPackage{ecdh1, ecdh3}, extPubkey)
	if err != nil {
		t.Fatalf("CombineEcdhPkgs failed: %v", err)
	}

	// Verify by computing direct scalar mult: ext_seckey * group_pk
	groupPt, err := ecc.LiftX(pkg.Group.GroupPk[:])
	if err != nil {
		t.Fatalf("LiftX failed: %v", err)
	}
	extScalar := ecc.ScalarFromBytes(extSeckey)
	directSharedPt := ecc.ScalarMulti(groupPt, extScalar)
	directShared := ecc.SerializePoint(directSharedPt)

	if !bytes.Equal(frostShared[:], directShared[:]) {
		t.Error("FROST ECDH shared secret must match direct computation")
	}

	// 5. Any threshold subset recovers the same secret
	secret12, err := shares.DeriveSharesSecret([]types.SecretShare{
		{ID: pkg.Shares[0].Idx, Seckey: pkg.Shares[0].Seckey},
		{ID: pkg.Shares[1].Idx, Seckey: pkg.Shares[1].Seckey},
	})
	if err != nil {
		t.Fatalf("DeriveSharesSecret failed for 1,2: %v", err)
	}

	secret13, err := shares.DeriveSharesSecret([]types.SecretShare{
		{ID: pkg.Shares[0].Idx, Seckey: pkg.Shares[0].Seckey},
		{ID: pkg.Shares[2].Idx, Seckey: pkg.Shares[2].Seckey},
	})
	if err != nil {
		t.Fatalf("DeriveSharesSecret failed for 1,3: %v", err)
	}

	secret23, err := shares.DeriveSharesSecret([]types.SecretShare{
		{ID: pkg.Shares[1].Idx, Seckey: pkg.Shares[1].Seckey},
		{ID: pkg.Shares[2].Idx, Seckey: pkg.Shares[2].Seckey},
	})
	if err != nil {
		t.Fatalf("DeriveSharesSecret failed for 2,3: %v", err)
	}

	if !bytes.Equal(secret12[:], secret13[:]) {
		t.Error("all subsets must recover the same secret: 12 != 13")
	}
	if !bytes.Equal(secret13[:], secret23[:]) {
		t.Error("all subsets must recover the same secret: 13 != 23")
	}

	// Verify recovered secret's public key equals group public key
	recoveredPk := helpers.GetPubkey(secret12)
	if !bytes.Equal(recoveredPk[:], pkg.Group.GroupPk[:]) {
		t.Error("recovered secret's pubkey must equal group_pk")
	}
}

// signMessage is a helper to run a complete signing round
func signMessage(t *testing.T, group *frost.GroupPackage, shares []frost.SharePackage, signerIndices [2]int, message []byte, tweaks [][32]byte) []frost.Signature {
	signerShares := []frost.SharePackage{shares[signerIndices[0]], shares[signerIndices[1]]}
	signerIdxs := []uint32{signerShares[0].Idx, signerShares[1].Idx}

	// Generate nonces
	noncePairs := []frost.DerivedNonce{
		frost.GenerateNoncePair(signerShares[0].Seckey),
		frost.GenerateNoncePair(signerShares[1].Seckey),
	}

	memberNonces := []frost.MemberNonce{
		frost.ToMemberNonce(noncePairs[0], signerShares[0].Idx),
		frost.ToMemberNonce(noncePairs[1], signerShares[1].Idx),
	}

	// Create session
	messages := []frost.SignMessage{
		{Message: message, Tweaks: tweaks},
	}
	session, err := frost.CreateSignSession(group, signerIdxs, messages, memberNonces)
	if err != nil {
		t.Fatalf("CreateSignSession failed: %v", err)
	}

	// Derive secret nonces and create partial sigs
	secretNonces := []frost.SecretNoncePair{
		frost.DeriveSecretNonce(signerShares[0].Seckey, noncePairs[0].Code),
		frost.DeriveSecretNonce(signerShares[1].Seckey, noncePairs[1].Code),
	}

	psigs := make([]frost.PartialSigPackage, 2)
	for i := 0; i < 2; i++ {
		psig, err := frost.CreatePartialSigPackage(&session, &signerShares[i], &secretNonces[i])
		if err != nil {
			t.Fatalf("CreatePartialSigPackage failed: %v", err)
		}

		// Verify partial sig
		reason, err := frost.VerifyPartialSigPackage(&session, group, &psig)
		if err != nil {
			t.Fatalf("VerifyPartialSigPackage failed: %v", err)
		}
		if reason != "" {
			t.Fatalf("partial sig invalid: %s", reason)
		}
		psigs[i] = psig
	}

	// Combine signatures
	signatures, err := frost.CombineSignatures(&session, group, psigs)
	if err != nil {
		t.Fatalf("CombineSignatures failed: %v", err)
	}

	return signatures
}

// TestDKGFullFlow tests the complete DKG flow.
func TestDKGFullFlow(t *testing.T) {
	// Three participants, threshold 2, fully deterministic seeds
	participantSeeds := [][][32]byte{
		{
			mustHexTo32("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
			mustHexTo32("1111111111111111111111111111111111111111111111111111111111111111"),
		},
		{
			mustHexTo32("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
			mustHexTo32("2222222222222222222222222222222222222222222222222222222222222222"),
		},
		{
			mustHexTo32("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"),
			mustHexTo32("3333333333333333333333333333333333333333333333333333333333333333"),
		},
	}

	// Round 1
	round1 := make([]struct {
		coeffs [][32]byte
		commit frost.DkgCommitPackage
	}, 3)

	for i := 0; i < 3; i++ {
		coeffs, commit := frost.DkgRound1(uint32(i+1), 2, participantSeeds[i])
		round1[i].coeffs = coeffs
		round1[i].commit = commit
	}

	allCommits := []frost.DkgCommitPackage{round1[0].commit, round1[1].commit, round1[2].commit}

	// Round 2
	allShares := []frost.DkgSharePackage{}
	for i := 0; i < 3; i++ {
		for j := 0; j < 3; j++ {
			share, err := frost.DkgRound2(uint32(i+1), round1[i].coeffs, uint32(j+1))
			if err != nil {
				t.Fatalf("DkgRound2 failed: %v", err)
			}
			allShares = append(allShares, share)
		}
	}

	// Finalize
	outputs := make([]frost.DkgOutput, 3)
	for i := 0; i < 3; i++ {
		myIdx := uint32(i + 1)

		// Collect received shares for this participant
		received := []frost.DkgSharePackage{}
		for _, s := range allShares {
			if s.RecipientIdx == myIdx && s.SenderIdx != myIdx {
				received = append(received, s)
			}
		}

		output, err := frost.DkgFinalize(myIdx, round1[i].coeffs, received, allCommits, 2)
		if err != nil {
			t.Fatalf("DkgFinalize failed for participant %d: %v", myIdx, err)
		}
		outputs[i] = output
	}

	// All participants must agree on the same group public key
	groupPk := outputs[0].Group.GroupPk
	for i, output := range outputs {
		if !bytes.Equal(output.Group.GroupPk[:], groupPk[:]) {
			t.Errorf("participant %d: group_pk mismatch", i+1)
		}
		if output.Group.Threshold != 2 {
			t.Errorf("participant %d: expected threshold 2, got %d", i+1, output.Group.Threshold)
		}
	}

	// Member pubkeys must be share pubkeys
	for _, output := range outputs {
		expectedPk := helpers.GetPubkey(output.Share.Seckey)
		var member *frost.MemberPackage
		for i := range output.Group.Members {
			if output.Group.Members[i].Idx == output.Share.Idx {
				member = &output.Group.Members[i]
				break
			}
		}
		if member == nil {
			t.Fatalf("member %d not found in group", output.Share.Idx)
		}
		if !bytes.Equal(member.Pubkey[:], expectedPk[:]) {
			t.Error("member.pubkey must equal share pubkey")
		}
	}

	// identity_pk must be set and equal to each participant's first VSS commit
	for i, output := range outputs {
		var commit *frost.DkgCommitPackage
		for j := range round1 {
			if round1[j].commit.Idx == output.Share.Idx {
				commit = &round1[j].commit
				break
			}
		}
		if commit == nil {
			t.Fatalf("commit for participant %d not found", output.Share.Idx)
		}

		var member *frost.MemberPackage
		for j := range output.Group.Members {
			if output.Group.Members[j].Idx == commit.Idx {
				member = &output.Group.Members[j]
				break
			}
		}
		if member == nil {
			t.Fatalf("member %d not found", commit.Idx)
		}

		if member.IdentityPk == nil {
			t.Errorf("participant %d: identity_pk must be set", i+1)
		} else if !bytes.Equal(member.IdentityPk[:], commit.VssCommits[0][:]) {
			t.Errorf("participant %d: identity_pk must equal first VSS commit", i+1)
		}
	}

	// All three 2-of-3 subsets can sign
	message := []byte("hello from the dkg flow")

	subsets := [][2]int{{0, 1}, {0, 2}, {1, 2}}
	for _, subset := range subsets {
		signerShares := []frost.SharePackage{outputs[subset[0]].Share, outputs[subset[1]].Share}
		group := outputs[0].Group

		sigs := signMessageDKG(t, &group, signerShares, message, nil)
		if len(sigs) != 1 {
			t.Fatalf("expected 1 signature, got %d", len(sigs))
		}
		if !bytes.Equal(sigs[0].Message, message) {
			t.Error("message mismatch in signature")
		}
		if !bytes.Equal(sigs[0].Pubkey[:], groupPk[:]) {
			t.Error("untweaked sig pubkey should equal group_pk")
		}
	}

	// Tweaked signing works
	tweak := mustHexTo32("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	tweakShares := []frost.SharePackage{outputs[0].Share, outputs[1].Share}
	tweakedSigs := signMessageDKG(t, &outputs[0].Group, tweakShares, message, [][32]byte{tweak})
	if len(tweakedSigs) != 1 {
		t.Fatalf("expected 1 tweaked signature, got %d", len(tweakedSigs))
	}
	if bytes.Equal(tweakedSigs[0].Pubkey[:], groupPk[:]) {
		t.Error("tweaked sig pubkey should differ from group_pk")
	}

	// Threshold ECDH
	extSeckey := mustHexTo32("1111111111111111111111111111111111111111111111111111111111111111")
	extPubkey := helpers.GetPubkey(extSeckey)

	ecdhMembers := []uint32{1, 3}
	sharesList := []frost.SharePackage{
		{Idx: outputs[0].Share.Idx, Seckey: outputs[0].Share.Seckey},
		{Idx: outputs[2].Share.Idx, Seckey: outputs[2].Share.Seckey},
	}
	ecdh1, err := frost.CreateEcdhPkg(ecdhMembers, extPubkey, &sharesList[0])
	if err != nil {
		t.Fatalf("CreateEcdhPkg failed: %v", err)
	}
	ecdh3, err := frost.CreateEcdhPkg(ecdhMembers, extPubkey, &sharesList[1])
	if err != nil {
		t.Fatalf("CreateEcdhPkg failed: %v", err)
	}
	frostShared, err := frost.CombineEcdhPkgs([]frost.EcdhPackage{ecdh1, ecdh3}, extPubkey)
	if err != nil {
		t.Fatalf("CombineEcdhPkgs failed: %v", err)
	}

	// Verify direct computation
	groupPt, err := ecc.LiftX(groupPk[:])
	if err != nil {
		t.Fatalf("LiftX failed: %v", err)
	}
	extScalar := ecc.ScalarFromBytes(extSeckey)
	directSharedPt := ecc.ScalarMulti(groupPt, extScalar)
	directShared := ecc.SerializePoint(directSharedPt)

	if !bytes.Equal(frostShared[:], directShared[:]) {
		t.Error("FROST ECDH shared secret must match direct computation")
	}

	// Secret recovery
	secret12, err := shares.DeriveSharesSecret([]types.SecretShare{
		{ID: outputs[0].Share.Idx, Seckey: outputs[0].Share.Seckey},
		{ID: outputs[1].Share.Idx, Seckey: outputs[1].Share.Seckey},
	})
	if err != nil {
		t.Fatalf("DeriveSharesSecret failed: %v", err)
	}
	secret13, err := shares.DeriveSharesSecret([]types.SecretShare{
		{ID: outputs[0].Share.Idx, Seckey: outputs[0].Share.Seckey},
		{ID: outputs[2].Share.Idx, Seckey: outputs[2].Share.Seckey},
	})
	if err != nil {
		t.Fatalf("DeriveSharesSecret failed: %v", err)
	}
	secret23, err := shares.DeriveSharesSecret([]types.SecretShare{
		{ID: outputs[1].Share.Idx, Seckey: outputs[1].Share.Seckey},
		{ID: outputs[2].Share.Idx, Seckey: outputs[2].Share.Seckey},
	})
	if err != nil {
		t.Fatalf("DeriveSharesSecret failed: %v", err)
	}

	if !bytes.Equal(secret12[:], secret13[:]) {
		t.Error("all subsets must recover the same secret: 12 != 13")
	}
	if !bytes.Equal(secret13[:], secret23[:]) {
		t.Error("all subsets must recover the same secret: 13 != 23")
	}

	recoveredPk := helpers.GetPubkey(secret12)
	if !bytes.Equal(recoveredPk[:], groupPk[:]) {
		t.Error("recovered secret's pubkey must equal group_pk")
	}

	// DKG group secret is the sum of all participants' constant terms
	sum := ecc.ScalarFromBytes(participantSeeds[0][0])
	for i := 1; i < len(participantSeeds); i++ {
		sum = ecc.ScalarAdd(sum, ecc.ScalarFromBytes(participantSeeds[i][0]))
	}
	expectedSecret := ecc.ScalarToBytes(sum)
	if !bytes.Equal(secret12[:], expectedSecret[:]) {
		t.Error("DKG secret must equal sum of participants' constant terms")
	}
}

// signMessageDKG is a helper for DKG signing
func signMessageDKG(t *testing.T, group *frost.GroupPackage, signerShares []frost.SharePackage, message []byte, tweaks [][32]byte) []frost.Signature {
	signerIdxs := []uint32{signerShares[0].Idx, signerShares[1].Idx}

	noncePairs := []frost.DerivedNonce{
		frost.GenerateNoncePair(signerShares[0].Seckey),
		frost.GenerateNoncePair(signerShares[1].Seckey),
	}

	memberNonces := []frost.MemberNonce{
		frost.ToMemberNonce(noncePairs[0], signerShares[0].Idx),
		frost.ToMemberNonce(noncePairs[1], signerShares[1].Idx),
	}

	messages := []frost.SignMessage{
		{Message: message, Tweaks: tweaks},
	}

	session, err := frost.CreateSignSession(group, signerIdxs, messages, memberNonces)
	if err != nil {
		t.Fatalf("CreateSignSession failed: %v", err)
	}

	secretNonces := []frost.SecretNoncePair{
		frost.DeriveSecretNonce(signerShares[0].Seckey, noncePairs[0].Code),
		frost.DeriveSecretNonce(signerShares[1].Seckey, noncePairs[1].Code),
	}

	psigs := make([]frost.PartialSigPackage, 2)
	for i := 0; i < 2; i++ {
		psig, err := frost.CreatePartialSigPackage(&session, &signerShares[i], &secretNonces[i])
		if err != nil {
			t.Fatalf("CreatePartialSigPackage failed: %v", err)
		}

		reason, err := frost.VerifyPartialSigPackage(&session, group, &psig)
		if err != nil {
			t.Fatalf("VerifyPartialSigPackage failed: %v", err)
		}
		if reason != "" {
			t.Fatalf("partial sig invalid: %s", reason)
		}
		psigs[i] = psig
	}

	signatures, err := frost.CombineSignatures(&session, group, psigs)
	if err != nil {
		t.Fatalf("CombineSignatures failed: %v", err)
	}

	return signatures
}
