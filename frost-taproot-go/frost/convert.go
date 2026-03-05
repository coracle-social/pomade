package frost

import "github.com/frost-taproot/frost-taproot-go/types"

func toSecretShare(share *SharePackage) types.SecretShare {
	return types.SecretShare{
		ID:     share.Idx,
		Seckey: share.Seckey,
	}
}

func toPublicNonces(nonces []MemberNonce) []types.PublicNonce {
	pnonces := make([]types.PublicNonce, len(nonces))
	for i, nonce := range nonces {
		pnonces[i] = types.PublicNonce{
			ID:       nonce.Idx,
			BinderPn: nonce.BinderPn,
			HiddenPn: nonce.HiddenPn,
		}
	}
	return pnonces
}
