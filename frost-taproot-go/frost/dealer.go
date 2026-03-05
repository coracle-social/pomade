// Package frost provides high-level FROST threshold signing API.
package frost

import (
	"crypto/sha256"
	"encoding/binary"

	"github.com/frost-taproot/frost-taproot-go/group"
	"github.com/frost-taproot/frost-taproot-go/helpers"
)

// GenerateDealerPackage generates a complete dealer package.
func GenerateDealerPackage(threshold int, shareCount uint32, secrets [][32]byte) (DealerPackage, error) {
	dealerSet, err := group.CreateDealerSet(threshold, shareCount, secrets)
	if err != nil {
		return DealerPackage{}, err
	}

	shares := make([]SharePackage, len(dealerSet.Shares))
	for i, s := range dealerSet.Shares {
		shares[i] = SharePackage{
			Idx:    s.ID,
			Seckey: s.Seckey,
		}
	}

	members := make([]MemberPackage, len(dealerSet.Shares))
	for i, s := range dealerSet.Shares {
		members[i] = MemberPackage{
			Idx:        s.ID,
			Pubkey:     helpers.GetPubkey(s.Seckey),
			IdentityPk: nil,
		}
	}

	grp := GroupPackage{
		GroupPk:   dealerSet.GroupPk,
		Threshold: threshold,
		Members:   members,
	}

	return DealerPackage{Group: grp, Shares: shares}, nil
}

// GetGroupId computes a stable group identifier.
func GetGroupId(group *GroupPackage) [32]byte {
	sorted := make([]MemberPackage, len(group.Members))
	copy(sorted, group.Members)
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j].Idx < sorted[i].Idx {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	h := sha256.New()
	h.Write(group.GroupPk[:])
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(group.Threshold))
	h.Write(buf)
	for _, m := range sorted {
		h.Write(m.Pubkey[:])
	}
	var out [32]byte
	h.Sum(out[:0])
	return out
}

// IsGroupMember checks if a share belongs to the given group.
func IsGroupMember(group *GroupPackage, share *SharePackage) bool {
	pubkey := helpers.GetPubkey(share.Seckey)
	for _, m := range group.Members {
		if m.Idx == share.Idx && m.Pubkey == pubkey {
			return true
		}
	}
	return false
}

// GetMemberByIdx looks up a member by index.
func GetMemberByIdx(group *GroupPackage, idx uint32) *MemberPackage {
	for i := range group.Members {
		if group.Members[i].Idx == idx {
			return &group.Members[i]
		}
	}
	return nil
}

// GetMemberByPubkey looks up a member by public key.
func GetMemberByPubkey(group *GroupPackage, pubkey [33]byte) *MemberPackage {
	for i := range group.Members {
		if group.Members[i].Pubkey == pubkey {
			return &group.Members[i]
		}
	}
	return nil
}
