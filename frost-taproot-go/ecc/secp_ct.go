// Constant-time secret operations backed by libsecp256k1.
//
// The pure-Go path in util.go wraps decred's secp256k1, whose scalar
// multiplications are the *NonConst variants: their running time depends on the
// scalar's bit pattern. That is fine for public data (signature verification,
// aggregation) but leaks the secret when the scalar is a key share or secret
// nonce. The functions here route every secret-dependent multiplication through
// libsecp256k1's constant-time primitives (ec_pubkey_create, ec_pubkey_tweak_mul,
// and the seckey tweak ops), so timing no longer correlates with the secret.
//
// Each exported wrapper takes the constant-time path for every input that can
// arise from a real secret (a valid scalar in [1, N-1]); the variable-time
// decred path is used only as a fallback for degenerate zero/out-of-range
// inputs, purely to reproduce the historic output. Such inputs never occur for
// genuine secrets, so nothing secret is ever handled in variable time.
package ecc

/*
#cgo pkg-config: libsecp256k1
#include <secp256k1.h>

// ct_context_create builds a context and randomizes it with the supplied
// 32-byte seed. Randomization re-blinds the internal state, hardening the
// constant-time operations against side-channel analysis. It is best-effort:
// on failure the (still usable) context is returned unrandomized.
static secp256k1_context* ct_context_create(const unsigned char* seed) {
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    if (ctx == NULL) {
        return NULL;
    }
    if (secp256k1_context_randomize(ctx, seed) != 1) {
        // Randomization only fails for the static context; ctx stays usable.
    }
    return ctx;
}

// ct_pubkey_serialize writes the 33-byte compressed encoding of pub into out.
static void ct_pubkey_serialize(const secp256k1_context* ctx, unsigned char* out, const secp256k1_pubkey* pub) {
    size_t len = 33;
    secp256k1_ec_pubkey_serialize(ctx, out, &len, pub, SECP256K1_EC_COMPRESSED);
}
*/
import "C"

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"sync"
	"unsafe"
)

var (
	ctxOnce sync.Once
	ctxPtr  *C.secp256k1_context
)

// ctContext lazily builds the process-wide, randomized libsecp256k1 context used
// for all constant-time secret operations. It is created once and only read
// afterwards, which libsecp256k1 documents as safe for concurrent use.
func ctContext() *C.secp256k1_context {
	ctxOnce.Do(func() {
		var seed [32]byte
		_, _ = rand.Read(seed[:]) // a zero seed still yields a valid context
		ctxPtr = C.ct_context_create((*C.uchar)(unsafe.Pointer(&seed[0])))
	})
	return ctxPtr
}

// scalarBaseMultCT returns the compressed point k*G, constant time wrt k.
// ok is false when k is not a valid secret scalar (zero or >= N).
func scalarBaseMultCT(k [32]byte) (out [33]byte, ok bool) {
	var pub C.secp256k1_pubkey
	if C.secp256k1_ec_pubkey_create(ctContext(), &pub, (*C.uchar)(unsafe.Pointer(&k[0]))) != 1 {
		return out, false
	}
	C.ct_pubkey_serialize(ctContext(), (*C.uchar)(unsafe.Pointer(&out[0])), &pub)
	return out, true
}

// pointScalarMultCT returns the compressed point k*P (P given compressed),
// constant time wrt k. ok is false when P is not a valid point or k is not a
// valid scalar.
func pointScalarMultCT(point [33]byte, k [32]byte) (out [33]byte, ok bool) {
	ctx := ctContext()
	var pub C.secp256k1_pubkey
	if C.secp256k1_ec_pubkey_parse(ctx, &pub, (*C.uchar)(unsafe.Pointer(&point[0])), 33) != 1 {
		return out, false
	}
	if C.secp256k1_ec_pubkey_tweak_mul(ctx, &pub, (*C.uchar)(unsafe.Pointer(&k[0]))) != 1 {
		return out, false
	}
	C.ct_pubkey_serialize(ctx, (*C.uchar)(unsafe.Pointer(&out[0])), &pub)
	return out, true
}

// seckeyTweakMulCT returns base*tweak mod N, constant time. ok is false when
// base is not a valid scalar or tweak is zero/>= N.
func seckeyTweakMulCT(base, tweak [32]byte) (out [32]byte, ok bool) {
	out = base
	if C.secp256k1_ec_seckey_tweak_mul(ctContext(), (*C.uchar)(unsafe.Pointer(&out[0])), (*C.uchar)(unsafe.Pointer(&tweak[0]))) != 1 {
		return [32]byte{}, false
	}
	return out, true
}

// seckeyTweakAddCT returns base+tweak mod N, constant time. ok is false when
// base is not a valid scalar or the result would be zero.
func seckeyTweakAddCT(base, tweak [32]byte) (out [32]byte, ok bool) {
	out = base
	if C.secp256k1_ec_seckey_tweak_add(ctContext(), (*C.uchar)(unsafe.Pointer(&out[0])), (*C.uchar)(unsafe.Pointer(&tweak[0]))) != 1 {
		return [32]byte{}, false
	}
	return out, true
}

// seckeyNegateCT returns -base mod N, constant time. ok is false when base is
// not a valid scalar.
func seckeyNegateCT(base [32]byte) (out [32]byte, ok bool) {
	out = base
	if C.secp256k1_ec_seckey_negate(ctContext(), (*C.uchar)(unsafe.Pointer(&out[0]))) != 1 {
		return [32]byte{}, false
	}
	return out, true
}

// ScalarBaseMultiCT returns the 33-byte compressed pubkey secret*G, computed in
// constant time wrt the secret scalar. The raw secret bytes are passed straight
// to the constant-time path; only a degenerate zero/out-of-range scalar (never a
// real secret) is rejected there and reduced via the variable-time fallback.
func ScalarBaseMultiCT(secret [32]byte) [33]byte {
	if out, ok := scalarBaseMultCT(secret); ok {
		return out
	}
	return SerializePoint(ScalarBaseMulti(ScalarFromBytes(secret)))
}

// ScalarMultiCT returns the 33-byte compressed point secret*P (P given as a
// 33-byte compressed point), computed in constant time wrt the secret scalar.
func ScalarMultiCT(point [33]byte, secret [32]byte) [33]byte {
	if out, ok := pointScalarMultCT(point, secret); ok {
		return out
	}
	p, err := DeserializePoint(point)
	if err != nil {
		return [33]byte{}
	}
	return SerializePoint(ScalarMulti(p, ScalarFromBytes(secret)))
}

// ScalarMulCT returns (secret * mult) mod N, constant time wrt the secret
// operand. mult is the public multiplier.
func ScalarMulCT(secret, mult [32]byte) [32]byte {
	if out, ok := seckeyTweakMulCT(secret, mult); ok {
		return out
	}
	return ScalarToBytes(ScalarMul(ScalarFromBytes(secret), ScalarFromBytes(mult)))
}

// ScalarAddCT returns (secret + addend) mod N, constant time wrt the secret
// operand.
func ScalarAddCT(secret, addend [32]byte) [32]byte {
	if out, ok := seckeyTweakAddCT(secret, addend); ok {
		return out
	}
	return ScalarToBytes(ScalarAdd(ScalarFromBytes(secret), ScalarFromBytes(addend)))
}

// ScalarNegCT returns (-secret) mod N, constant time wrt the secret.
func ScalarNegCT(secret [32]byte) [32]byte {
	if out, ok := seckeyNegateCT(secret); ok {
		return out
	}
	return ScalarToBytes(ScalarNeg(ScalarFromBytes(secret)))
}

// nMinus2 holds the 32 big-endian bytes of N-2, the fixed Fermat exponent used
// by ScalarInvertCT.
var nMinus2 = func() [32]byte {
	e := new(big.Int).Sub(N, big.NewInt(2))
	var out [32]byte
	b := e.Bytes()
	copy(out[32-len(b):], b)
	return out
}()

// ScalarInvertCT returns the modular inverse of secret mod N, computed in
// constant time wrt the secret via Fermat's little theorem: secret^(N-2) mod N.
// The exponent N-2 is a fixed public constant, so the square-and-multiply
// schedule is data independent. Every intermediate power of a nonzero scalar is
// nonzero mod the prime N, so each step stays a valid scalar for the
// constant-time ScalarMulCT. A zero (non-invertible) secret falls back to the
// variable-time ScalarInvert, which returns an error; such inputs never arise
// from a real secret.
func ScalarInvertCT(secret [32]byte) ([32]byte, error) {
	if ScalarFromBytes(secret).Sign() == 0 {
		return [32]byte{}, fmt.Errorf("scalar inversion failed: zero scalar")
	}

	// result = 1, accumulated as a scalar in [1, N-1].
	var result [32]byte
	result[31] = 1
	resultIsOne := true

	for _, byteVal := range nMinus2 {
		for bit := 7; bit >= 0; bit-- {
			// Square: result = result * result. Skip while result is still the
			// identity (1*1 == 1) so the first squaring keeps a valid scalar.
			if !resultIsOne {
				result = ScalarMulCT(result, result)
			}
			if (byteVal>>uint(bit))&1 == 1 {
				if resultIsOne {
					result = secret
					resultIsOne = false
				} else {
					result = ScalarMulCT(result, secret)
				}
			}
		}
	}
	return result, nil
}
