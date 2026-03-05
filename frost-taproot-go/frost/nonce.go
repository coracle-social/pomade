// Package frost provides high-level FROST threshold signing API.
package frost

import (
	"crypto/hmac"
	"crypto/sha256"

	"github.com/frost-taproot/frost-taproot-go/ecc"
	"github.com/frost-taproot/frost-taproot-go/helpers"
)

var (
	domainBinder = []byte("bifrost/nonce/binder/v1")
	domainHidden = []byte("bifrost/nonce/hidden/v1")
)

func deriveNonceSecret(shareSecret, code [32]byte, domain []byte) [32]byte {
	mac := hmac.New(sha256.New, shareSecret[:])
	mac.Write(code[:])
	mac.Write(domain)
	var out [32]byte
	copy(out[:], mac.Sum(nil))
	return out
}

// GenerateNoncePair generates a fresh nonce pair from a share secret.
func GenerateNoncePair(shareSecret [32]byte) DerivedNonce {
	code := ecc.RandomBytes32()
	binderSn := deriveNonceSecret(shareSecret, code, domainBinder)
	hiddenSn := deriveNonceSecret(shareSecret, code, domainHidden)
	binderPn := helpers.GetPubkey(binderSn)
	hiddenPn := helpers.GetPubkey(hiddenSn)
	return DerivedNonce{
		BinderPn: binderPn,
		HiddenPn: hiddenPn,
		Code:     code,
	}
}

// GenerateNoncePairs generates multiple nonce pairs.
func GenerateNoncePairs(shareSecret [32]byte, count int) []DerivedNonce {
	nonces := make([]DerivedNonce, count)
	for i := 0; i < count; i++ {
		nonces[i] = GenerateNoncePair(shareSecret)
	}
	return nonces
}

// DeriveSecretNonce re-derives secret nonce from code.
func DeriveSecretNonce(shareSecret, code [32]byte) SecretNoncePair {
	binderSn := deriveNonceSecret(shareSecret, code, domainBinder)
	hiddenSn := deriveNonceSecret(shareSecret, code, domainHidden)
	return SecretNoncePair{
		Code:     code,
		BinderSn: binderSn,
		HiddenSn: hiddenSn,
	}
}

// VerifyNonceCode verifies that a code produces expected public nonces.
func VerifyNonceCode(shareSecret [32]byte, nonce *MemberNonce) bool {
	derived := DeriveSecretNonce(shareSecret, nonce.Code)
	binderPn := helpers.GetPubkey(derived.BinderSn)
	hiddenPn := helpers.GetPubkey(derived.HiddenSn)
	return binderPn == nonce.BinderPn && hiddenPn == nonce.HiddenPn
}

// ToMemberNonce attaches a member index to a DerivedNonce.
func ToMemberNonce(nonce DerivedNonce, idx uint32) MemberNonce {
	return MemberNonce{
		Idx:      idx,
		BinderPn: nonce.BinderPn,
		HiddenPn: nonce.HiddenPn,
		Code:     nonce.Code,
	}
}

// ValidateNonce validates that a DerivedNonce contains valid curve points.
func ValidateNonce(nonce *DerivedNonce) bool {
	_, err1 := ecc.LiftX(nonce.BinderPn[:])
	_, err2 := ecc.LiftX(nonce.HiddenPn[:])
	return err1 == nil && err2 == nil
}
