package integration

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/frost-taproot/frost-taproot-go/commit"
	"github.com/frost-taproot/frost-taproot-go/context"
	"github.com/frost-taproot/frost-taproot-go/group"
	"github.com/frost-taproot/frost-taproot-go/sign"
	"github.com/frost-taproot/frost-taproot-go/types"
)

// Fixture represents the test fixture data.
type Fixture struct {
	Secrets    []string `json:"secrets"`
	Threshold  int      `json:"threshold"`
	ShareMax   int      `json:"share_max"`
	Message    string   `json:"message"`
	HiddenSeed string   `json:"hidden_seed"`
	BinderSeed string   `json:"binder_seed"`
	Tweaks     []string `json:"tweaks"`
	GroupPk    string   `json:"group_pk"`
	VssCommits []string `json:"vss_commits"`
	Shares     []struct {
		Idx    int    `json:"idx"`
		Seckey string `json:"seckey"`
	} `json:"shares"`
	Commits []struct {
		Idx      int    `json:"idx"`
		HiddenSn string `json:"hidden_sn"`
		BinderSn string `json:"binder_sn"`
		HiddenPn string `json:"hidden_pn"`
		BinderPn string `json:"binder_pn"`
	} `json:"commits"`
	Ctx struct {
		GroupPk     string `json:"group_pk"`
		GroupPn     string `json:"group_pn"`
		BindPrefix  string `json:"bind_prefix"`
		BindFactors []struct {
			Idx    int    `json:"idx"`
			Factor string `json:"factor"`
		} `json:"bind_factors"`
		Challenge string `json:"challenge"`
		Indexes   []int  `json:"indexes"`
		Message   string `json:"message"`
	} `json:"ctx"`
	Psigs []struct {
		Idx    int    `json:"idx"`
		Pubkey string `json:"pubkey"`
		Psig   string `json:"psig"`
	} `json:"psigs"`
	Signature string `json:"signature"`
}

var fx Fixture

func init() {
	data, err := os.ReadFile("fixture.json")
	if err != nil {
		panic(err)
	}
	if err := json.Unmarshal(data, &fx); err != nil {
		panic(err)
	}
}

// Helper functions
func mustHexTo32(s string) [32]byte {
	b, err := hexToBytes(s)
	if err != nil {
		panic(err)
	}
	var out [32]byte
	copy(out[:], b)
	return out
}

func mustHexTo33(s string) [33]byte {
	b, err := hexToBytes(s)
	if err != nil {
		panic(err)
	}
	var out [33]byte
	copy(out[:], b)
	return out
}

func mustHexToBytes(s string) []byte {
	b, err := hexToBytes(s)
	if err != nil {
		panic(err)
	}
	return b
}

func hexToBytes(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("invalid hex length")
	}
	result := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		hi := hexValue(s[i])
		lo := hexValue(s[i+1])
		if hi < 0 || lo < 0 {
			return nil, fmt.Errorf("invalid hex char")
		}
		result[i/2] = byte(hi<<4 | lo)
	}
	return result, nil
}

func hexValue(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c - 'a' + 10)
	case c >= 'A' && c <= 'F':
		return int(c - 'A' + 10)
	}
	return -1
}

func bytesToHex(b []byte) string {
	const hexChars = "0123456789abcdef"
	result := make([]byte, len(b)*2)
	for i, v := range b {
		result[i*2] = hexChars[v>>4]
		result[i*2+1] = hexChars[v&0x0f]
	}
	return string(result)
}

// TestDealerSetMatchesTS tests dealer set creation matches the TypeScript reference.
func TestDealerSetMatchesTS(t *testing.T) {
	secrets := make([][32]byte, len(fx.Secrets))
	for i, s := range fx.Secrets {
		secrets[i] = mustHexTo32(s)
	}

	grp, err := group.CreateDealerSet(fx.Threshold, uint32(fx.ShareMax), secrets)
	if err != nil {
		t.Fatalf("CreateDealerSet failed: %v", err)
	}

	if bytesToHex(grp.GroupPk[:]) != fx.GroupPk {
		t.Errorf("group_pk mismatch: got %s, want %s", bytesToHex(grp.GroupPk[:]), fx.GroupPk)
	}

	for i, expected := range fx.VssCommits {
		if bytesToHex(grp.VssCommits[i][:]) != expected {
			t.Errorf("vss_commit[%d] mismatch: got %s, want %s", i, bytesToHex(grp.VssCommits[i][:]), expected)
		}
	}

	for _, expected := range fx.Shares {
		var share *types.SecretShare
		for i := range grp.Shares {
			if grp.Shares[i].ID == uint32(expected.Idx) {
				share = &grp.Shares[i]
				break
			}
		}
		if share == nil {
			t.Errorf("share %d not found", expected.Idx)
			continue
		}
		if bytesToHex(share.Seckey[:]) != expected.Seckey {
			t.Errorf("share[%d].seckey mismatch: got %s, want %s", expected.Idx, bytesToHex(share.Seckey[:]), expected.Seckey)
		}
	}
}

// TestNonceCommitmentsMatchTS tests nonce generation matches the TypeScript reference.
func TestNonceCommitmentsMatchTS(t *testing.T) {
	for _, c := range fx.Commits {
		var shareSeckey string
		for _, s := range fx.Shares {
			if s.Idx == c.Idx {
				shareSeckey = s.Seckey
				break
			}
		}

		share := types.SecretShare{
			ID:     uint32(c.Idx),
			Seckey: mustHexTo32(shareSeckey),
		}
		hiddenSeed := mustHexTo32(fx.HiddenSeed)
		binderSeed := mustHexTo32(fx.BinderSeed)

		commitPkg := commit.CreateCommitPkg(&share, &hiddenSeed, &binderSeed)

		if bytesToHex(commitPkg.HiddenSn[:]) != c.HiddenSn {
			t.Errorf("hidden_sn mismatch for idx %d: got %s, want %s", c.Idx, bytesToHex(commitPkg.HiddenSn[:]), c.HiddenSn)
		}
		if bytesToHex(commitPkg.BinderSn[:]) != c.BinderSn {
			t.Errorf("binder_sn mismatch for idx %d: got %s, want %s", c.Idx, bytesToHex(commitPkg.BinderSn[:]), c.BinderSn)
		}
		if bytesToHex(commitPkg.HiddenPn[:]) != c.HiddenPn {
			t.Errorf("hidden_pn mismatch for idx %d: got %s, want %s", c.Idx, bytesToHex(commitPkg.HiddenPn[:]), c.HiddenPn)
		}
		if bytesToHex(commitPkg.BinderPn[:]) != c.BinderPn {
			t.Errorf("binder_pn mismatch for idx %d: got %s, want %s", c.Idx, bytesToHex(commitPkg.BinderPn[:]), c.BinderPn)
		}
	}
}

// TestSigningContextMatchesTS tests signing context matches the TypeScript reference.
func TestSigningContextMatchesTS(t *testing.T) {
	pnonces := make([]types.PublicNonce, len(fx.Commits))
	for i, c := range fx.Commits {
		pnonces[i] = types.PublicNonce{
			ID:       uint32(c.Idx),
			HiddenPn: mustHexTo33(c.HiddenPn),
			BinderPn: mustHexTo33(c.BinderPn),
		}
	}

	tweaks := make([][32]byte, len(fx.Tweaks))
	for i, tw := range fx.Tweaks {
		tweaks[i] = mustHexTo32(tw)
	}
	message := mustHexToBytes(fx.Message)
	groupPk := mustHexTo33(fx.GroupPk)

	ctx, err := context.GetGroupSigningCtx(groupPk[:], pnonces, message, tweaks)
	if err != nil {
		t.Fatalf("GetGroupSigningCtx failed: %v", err)
	}

	if bytesToHex(ctx.GroupPk[:]) != fx.Ctx.GroupPk {
		t.Errorf("ctx.group_pk mismatch: got %s, want %s", bytesToHex(ctx.GroupPk[:]), fx.Ctx.GroupPk)
	}
	if bytesToHex(ctx.GroupPn[:]) != fx.Ctx.GroupPn {
		t.Errorf("ctx.group_pn mismatch: got %s, want %s", bytesToHex(ctx.GroupPn[:]), fx.Ctx.GroupPn)
	}
	if bytesToHex(ctx.BindPrefix) != fx.Ctx.BindPrefix {
		t.Errorf("ctx.bind_prefix mismatch: got %s, want %s", bytesToHex(ctx.BindPrefix), fx.Ctx.BindPrefix)
	}

	for _, expected := range fx.Ctx.BindFactors {
		var bf *types.BindFactor
		for i := range ctx.BindFactors {
			if ctx.BindFactors[i].ID == uint32(expected.Idx) {
				bf = &ctx.BindFactors[i]
				break
			}
		}
		if bf == nil {
			t.Errorf("bind_factor %d not found", expected.Idx)
			continue
		}
		if bytesToHex(bf.Factor[:]) != expected.Factor {
			t.Errorf("bind_factor[%d] mismatch: got %s, want %s", expected.Idx, bytesToHex(bf.Factor[:]), expected.Factor)
		}
	}

	if bytesToHex(ctx.Challenge[:]) != fx.Ctx.Challenge {
		t.Errorf("challenge mismatch: got %s, want %s", bytesToHex(ctx.Challenge[:]), fx.Ctx.Challenge)
	}
}

// TestPartialSignaturesMatchTS tests partial signatures match the TypeScript reference.
func TestPartialSignaturesMatchTS(t *testing.T) {
	pnonces := make([]types.PublicNonce, len(fx.Commits))
	for i, c := range fx.Commits {
		pnonces[i] = types.PublicNonce{
			ID:       uint32(c.Idx),
			HiddenPn: mustHexTo33(c.HiddenPn),
			BinderPn: mustHexTo33(c.BinderPn),
		}
	}

	tweaks := make([][32]byte, len(fx.Tweaks))
	for i, tw := range fx.Tweaks {
		tweaks[i] = mustHexTo32(tw)
	}
	message := mustHexToBytes(fx.Message)
	groupPk := mustHexTo33(fx.GroupPk)

	ctx, err := context.GetGroupSigningCtx(groupPk[:], pnonces, message, tweaks)
	if err != nil {
		t.Fatalf("GetGroupSigningCtx failed: %v", err)
	}

	for _, expected := range fx.Psigs {
		var shareSeckey string
		for _, s := range fx.Shares {
			if s.Idx == expected.Idx {
				shareSeckey = s.Seckey
				break
			}
		}

		share := types.SecretShare{
			ID:     uint32(expected.Idx),
			Seckey: mustHexTo32(shareSeckey),
		}

		var commitData struct {
			Idx      int    `json:"idx"`
			HiddenSn string `json:"hidden_sn"`
			BinderSn string `json:"binder_sn"`
			HiddenPn string `json:"hidden_pn"`
			BinderPn string `json:"binder_pn"`
		}
		for _, c := range fx.Commits {
			if c.Idx == expected.Idx {
				commitData = c
				break
			}
		}

		snonce := types.SecretNonce{
			ID:       uint32(expected.Idx),
			HiddenSn: mustHexTo32(commitData.HiddenSn),
			BinderSn: mustHexTo32(commitData.BinderSn),
		}

		sig, err := sign.SignMsg(&ctx, &share, &snonce)
		if err != nil {
			t.Fatalf("SignMsg failed for idx %d: %v", expected.Idx, err)
		}

		if bytesToHex(sig.Pubkey[:]) != expected.Pubkey {
			t.Errorf("psig[%d].pubkey mismatch: got %s, want %s", expected.Idx, bytesToHex(sig.Pubkey[:]), expected.Pubkey)
		}
		if bytesToHex(sig.Psig[:]) != expected.Psig {
			t.Errorf("psig[%d].psig mismatch: got %s, want %s", expected.Idx, bytesToHex(sig.Psig[:]), expected.Psig)
		}
	}
}

// TestPartialSigVerification verifies partial signatures.
func TestPartialSigVerification(t *testing.T) {
	pnonces := make([]types.PublicNonce, len(fx.Commits))
	for i, c := range fx.Commits {
		pnonces[i] = types.PublicNonce{
			ID:       uint32(c.Idx),
			HiddenPn: mustHexTo33(c.HiddenPn),
			BinderPn: mustHexTo33(c.BinderPn),
		}
	}

	tweaks := make([][32]byte, len(fx.Tweaks))
	for i, tw := range fx.Tweaks {
		tweaks[i] = mustHexTo32(tw)
	}
	message := mustHexToBytes(fx.Message)
	groupPk := mustHexTo33(fx.GroupPk)

	ctx, err := context.GetGroupSigningCtx(groupPk[:], pnonces, message, tweaks)
	if err != nil {
		t.Fatalf("GetGroupSigningCtx failed: %v", err)
	}

	for _, expected := range fx.Psigs {
		var pnonce *types.PublicNonce
		for i := range pnonces {
			if pnonces[i].ID == uint32(expected.Idx) {
				pnonce = &pnonces[i]
				break
			}
		}
		if pnonce == nil {
			t.Fatalf("no pnonce for idx %d", expected.Idx)
		}

		sharePk := mustHexTo33(expected.Pubkey)
		sharePsig := mustHexTo32(expected.Psig)

		ok, err := sign.VerifyPartialSig(&ctx, pnonce, sharePk, sharePsig)
		if err != nil {
			t.Fatalf("VerifyPartialSig failed for idx %d: %v", expected.Idx, err)
		}
		if !ok {
			t.Errorf("partial sig verification failed for idx %d", expected.Idx)
		}
	}
}

// TestFinalSignatureMatchesTS tests the final aggregated signature.
func TestFinalSignatureMatchesTS(t *testing.T) {
	pnonces := make([]types.PublicNonce, len(fx.Commits))
	for i, c := range fx.Commits {
		pnonces[i] = types.PublicNonce{
			ID:       uint32(c.Idx),
			HiddenPn: mustHexTo33(c.HiddenPn),
			BinderPn: mustHexTo33(c.BinderPn),
		}
	}

	tweaks := make([][32]byte, len(fx.Tweaks))
	for i, tw := range fx.Tweaks {
		tweaks[i] = mustHexTo32(tw)
	}
	message := mustHexToBytes(fx.Message)
	groupPk := mustHexTo33(fx.GroupPk)

	ctx, err := context.GetGroupSigningCtx(groupPk[:], pnonces, message, tweaks)
	if err != nil {
		t.Fatalf("GetGroupSigningCtx failed: %v", err)
	}

	psigs := make([]types.ShareSignature, len(fx.Psigs))
	for i, p := range fx.Psigs {
		psigs[i] = types.ShareSignature{
			ID:     uint32(p.Idx),
			Pubkey: mustHexTo33(p.Pubkey),
			Psig:   mustHexTo32(p.Psig),
		}
	}

	sig, err := sign.CombinePartialSigs(&ctx, psigs)
	if err != nil {
		t.Fatalf("CombinePartialSigs failed: %v", err)
	}

	if bytesToHex(sig[:]) != fx.Signature {
		t.Errorf("final signature mismatch: got %s, want %s", bytesToHex(sig[:]), fx.Signature)
	}

	keyCtx := ctx.KeyContext()
	valid, err := sign.VerifyFinalSig(&keyCtx, message, sig)
	if err != nil {
		t.Fatalf("VerifyFinalSig failed: %v", err)
	}
	if !valid {
		t.Error("final signature failed BIP340 verification")
	}
}
