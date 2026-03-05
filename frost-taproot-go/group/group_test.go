package group

import (
	"testing"

	"github.com/frost-taproot/frost-taproot-go/shares"
)

func s32(hex string) [32]byte {
	b := decodeHex(hex)
	var out [32]byte
	copy(out[:], b)
	return out
}

func toHex(b []byte) string {
	const chars = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = chars[v>>4]
		out[i*2+1] = chars[v&0xf]
	}
	return string(out)
}

func decodeHex(s string) []byte {
	b := make([]byte, len(s)/2)
	for i := range b {
		b[i] = nibble(s[i*2])<<4 | nibble(s[i*2+1])
	}
	return b
}

func nibble(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	}
	return 0
}

const (
	s0hex = "0070ca75929ca1ec4cd70ac34f46079bdfdd87f9d0c0bf4275f3882f7b462d0f"
	s1hex = "0e0376a7180253cdb8b6020bff0eda529760da65e715663e2152e4be2fc7b443"
)

// ── CreateShareSet ────────────────────────────────────────────────────────────

func TestCreateShareSetCorrectCounts(t *testing.T) {
	set, err := CreateShareSet(2, 3, [][32]byte{s32(s0hex), s32(s1hex)})
	if err != nil {
		t.Fatalf("CreateShareSet failed: %v", err)
	}
	if len(set.Shares) != 3 {
		t.Errorf("expected 3 shares, got %d", len(set.Shares))
	}
	if len(set.VssCommits) != 2 {
		t.Errorf("expected 2 VSS commits, got %d", len(set.VssCommits))
	}
}

func TestCreateShareSetSharesAreValid(t *testing.T) {
	set, err := CreateShareSet(2, 3, [][32]byte{s32(s0hex), s32(s1hex)})
	if err != nil {
		t.Fatalf("CreateShareSet failed: %v", err)
	}
	for _, s := range set.Shares {
		ok, err := shares.VerifyShare(set.VssCommits, &s, 2)
		if err != nil {
			t.Fatalf("VerifyShare error for idx %d: %v", s.ID, err)
		}
		if !ok {
			t.Errorf("share %d should pass VSS verification", s.ID)
		}
	}
}

func TestCreateShareSetVssCommitsMatchFixture(t *testing.T) {
	set, err := CreateShareSet(2, 3, [][32]byte{s32(s0hex), s32(s1hex)})
	if err != nil {
		t.Fatalf("CreateShareSet failed: %v", err)
	}
	want0 := "021ae63bc9ddaffe52d44c3018e83115bfb22195bd8112fcad112310714e6fd5ec"
	want1 := "024f75a5478deda1102eba931e19425e59c1750533a54218ce215ced343fbfb6cf"
	if toHex(set.VssCommits[0][:]) != want0 {
		t.Errorf("vss_commit[0] mismatch:\n  got  %s\n  want %s", toHex(set.VssCommits[0][:]), want0)
	}
	if toHex(set.VssCommits[1][:]) != want1 {
		t.Errorf("vss_commit[1] mismatch:\n  got  %s\n  want %s", toHex(set.VssCommits[1][:]), want1)
	}
}

// ── CreateDealerSet ───────────────────────────────────────────────────────────

func TestCreateDealerSetGroupPkIsFirstCommit(t *testing.T) {
	set, err := CreateDealerSet(2, 3, [][32]byte{s32(s0hex), s32(s1hex)})
	if err != nil {
		t.Fatalf("CreateDealerSet failed: %v", err)
	}
	if set.GroupPk != set.VssCommits[0] {
		t.Error("group_pk must equal the first VSS commit")
	}
}

func TestCreateDealerSetGroupPkMatchesFixture(t *testing.T) {
	set, err := CreateDealerSet(2, 3, [][32]byte{s32(s0hex), s32(s1hex)})
	if err != nil {
		t.Fatalf("CreateDealerSet failed: %v", err)
	}
	want := "021ae63bc9ddaffe52d44c3018e83115bfb22195bd8112fcad112310714e6fd5ec"
	if toHex(set.GroupPk[:]) != want {
		t.Errorf("group_pk mismatch:\n  got  %s\n  want %s", toHex(set.GroupPk[:]), want)
	}
}

func TestCreateDealerSetSharesMatchFixture(t *testing.T) {
	set, err := CreateDealerSet(2, 3, [][32]byte{s32(s0hex), s32(s1hex)})
	if err != nil {
		t.Fatalf("CreateDealerSet failed: %v", err)
	}
	want := []string{
		"0e74411caa9ef5ba058d0ccf4e54e1ee773e625fb7d6258097466cedab0de152",
		"1c77b7c3c2a14987be430edb4d63bc410e9f3cc59eeb8bbeb89951abdad59595",
		"2a7b2e6adaa39d5576f910e74c729693a600172b8600f1fcd9ec366a0a9d49d8",
	}
	for i, s := range set.Shares {
		if toHex(s.Seckey[:]) != want[i] {
			t.Errorf("share[%d] seckey mismatch:\n  got  %s\n  want %s", i, toHex(s.Seckey[:]), want[i])
		}
	}
}

func TestCreateDealerSetNoSecretsIsRandom(t *testing.T) {
	a, err := CreateDealerSet(2, 3, nil)
	if err != nil {
		t.Fatalf("CreateDealerSet failed: %v", err)
	}
	b, err := CreateDealerSet(2, 3, nil)
	if err != nil {
		t.Fatalf("CreateDealerSet failed: %v", err)
	}
	if a.GroupPk == b.GroupPk {
		t.Error("two random dealer sets must produce different group public keys")
	}
}
