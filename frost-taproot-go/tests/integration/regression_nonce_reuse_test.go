package integration

// Regression test for the nonce-reuse share-recovery vulnerability.
//
// Original bug: a SignSession carried a list of messages but only one nonce per
// member, and CreatePartialSigPackage signed every message with that single
// reused nonce. Three messages then formed a solvable 3-unknown linear system
// (seckey, hidden_sn, binder_sn), letting a co-signer or coordinator recover the
// victim's secret share from its own partial signatures.
//
// Fix: a session is structurally single-message — CreateSignSession rejects any
// message list whose length isn't exactly 1, so one fresh nonce can never sign
// more than one message.

import (
	"testing"

	"github.com/frost-taproot/frost-taproot-go/frost"
)

func repByte(b byte) [32]byte {
	var out [32]byte
	for i := range out {
		out[i] = b
	}
	return out
}

func TestMultiMessageSessionIsRejected(t *testing.T) {
	pkg, err := frost.GenerateDealerPackage(2, 3, [][32]byte{repByte(0x11), repByte(0x22)})
	if err != nil {
		t.Fatal(err)
	}
	signers := pkg.Shares[:2]

	memberNonces := make([]frost.MemberNonce, len(signers))
	for i, s := range signers {
		memberNonces[i] = frost.ToMemberNonce(frost.GenerateNoncePair(s.Seckey), s.Idx)
	}

	// The attack needed THREE messages under one nonce. The session must refuse
	// to be built at all, so the partial sigs that leak the share never exist.
	messages := []frost.SignMessage{
		{Message: []byte("transfer 1 BTC to alice")},
		{Message: []byte("transfer 2 BTC to bob")},
		{Message: []byte("transfer 3 BTC to carol")},
	}
	_, err = frost.CreateSignSession(&pkg.Group, []uint32{1, 2}, messages, memberNonces)
	if err == nil {
		t.Fatal("multi-message session must be rejected — it is the precondition for nonce-reuse share recovery")
	}
}

func TestSingleMessageSessionStillSigns(t *testing.T) {
	pkg, err := frost.GenerateDealerPackage(2, 3, [][32]byte{repByte(0x11), repByte(0x22)})
	if err != nil {
		t.Fatal(err)
	}
	signers := pkg.Shares[:2]

	noncePairs := make([]frost.DerivedNonce, len(signers))
	memberNonces := make([]frost.MemberNonce, len(signers))
	secretNonces := make([]frost.SecretNoncePair, len(signers))
	for i, s := range signers {
		noncePairs[i] = frost.GenerateNoncePair(s.Seckey)
		memberNonces[i] = frost.ToMemberNonce(noncePairs[i], s.Idx)
		secretNonces[i] = frost.DeriveSecretNonce(s.Seckey, noncePairs[i].Code)
	}

	messages := []frost.SignMessage{{Message: []byte("transfer 1 BTC to alice")}}
	session, err := frost.CreateSignSession(&pkg.Group, []uint32{1, 2}, messages, memberNonces)
	if err != nil {
		t.Fatal(err)
	}

	psigs := make([]frost.PartialSigPackage, len(signers))
	for i := range signers {
		psig, err := frost.CreatePartialSigPackage(&session, &signers[i], &secretNonces[i])
		if err != nil {
			t.Fatal(err)
		}
		if len(psig.Psigs) != 1 {
			t.Fatalf("one message => one partial sig, got %d", len(psig.Psigs))
		}
		psigs[i] = psig
	}

	sigs, err := frost.CombineSignatures(&session, &pkg.Group, psigs)
	if err != nil {
		t.Fatal(err)
	}
	if len(sigs) != 1 {
		t.Fatalf("expected 1 signature, got %d", len(sigs))
	}
}
