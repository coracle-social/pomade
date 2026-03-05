// Package frost provides high-level FROST threshold signing API.
package frost

import (
	"github.com/frost-taproot/frost-taproot-go/ecdh"
	"github.com/frost-taproot/frost-taproot-go/types"
)

// CreateEcdhPkg creates an ECDH package for a single target public key.
func CreateEcdhPkg(members []uint32, ecdhPk [33]byte, share *SharePackage) (EcdhPackage, error) {
	lowShare := types.SecretShare{
		ID:     share.Idx,
		Seckey: share.Seckey,
	}
	ecdhShare, err := ecdh.CreateEcdhShare(members, &lowShare, ecdhPk[:])
	if err != nil {
		return EcdhPackage{}, err
	}
	return EcdhPackage{
		Idx:     share.Idx,
		Members: members,
		Entries: []EcdhEntry{{EcdhPk: ecdhPk, Keyshare: ecdhShare.Pubkey}},
	}, nil
}

// CreateBatchedEcdhPkg creates an ECDH package for multiple target keys.
func CreateBatchedEcdhPkg(members []uint32, ecdhPks [][33]byte, share *SharePackage) (EcdhPackage, error) {
	lowShare := types.SecretShare{
		ID:     share.Idx,
		Seckey: share.Seckey,
	}
	entries := make([]EcdhEntry, len(ecdhPks))
	for i, pk := range ecdhPks {
		ecdhShare, err := ecdh.CreateEcdhShare(members, &lowShare, pk[:])
		if err != nil {
			return EcdhPackage{}, err
		}
		entries[i] = EcdhEntry{EcdhPk: pk, Keyshare: ecdhShare.Pubkey}
	}
	return EcdhPackage{
		Idx:     share.Idx,
		Members: members,
		Entries: entries,
	}, nil
}

// CombineEcdhPkgs combines ECDH packages to derive the shared secret.
func CombineEcdhPkgs(pkgs []EcdhPackage, ecdhPk [33]byte) ([33]byte, error) {
	keyshares := make([]types.PublicShare, len(pkgs))
	for i, pkg := range pkgs {
		var entry *EcdhEntry
		for j := range pkg.Entries {
			if pkg.Entries[j].EcdhPk == ecdhPk {
				entry = &pkg.Entries[j]
				break
			}
		}
		if entry == nil {
			return [33]byte{}, &ErrNotFound{}
		}
		keyshares[i] = types.PublicShare{
			ID:     pkg.Idx,
			Pubkey: entry.Keyshare,
		}
	}
	return ecdh.DeriveEcdhSecret(keyshares)
}

// ErrNotFound indicates a key was not found.
type ErrNotFound struct{}

func (e *ErrNotFound) Error() string { return "not found" }
