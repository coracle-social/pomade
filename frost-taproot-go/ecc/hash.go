// Package ecc provides elliptic curve operations for secp256k1.
package ecc

import (
	"crypto/sha256"
	"encoding/binary"
	"math/big"
)

const domain = "FROST-secp256k1-SHA256-v1"

// dst builds the domain separation tag.
func dst(sub string) []byte {
	return []byte(domain + sub)
}

// hashToFieldN hashes a message to a scalar mod N using XMD.
func hashToFieldN(msg, dstBytes []byte) *big.Int {
	// expand_message_xmd to 48 bytes using SHA-256
	uniform := expandMsgXmd(msg, dstBytes, 48)

	// Split into high 16 bytes and low 32 bytes
	hi16 := uniform[:16]
	lo32 := uniform[16:]

	// lo_scalar
	var loArr [32]byte
	copy(loArr[:], lo32)
	loScalar := ScalarFromBytes(loArr)

	// 2^256 mod N
	two256ModN, _ := new(big.Int).SetString("014551231950B75FC4402DA1732FC9BEBF", 16)

	// hi_scalar (16 bytes padded to 32)
	var hiArr [32]byte
	copy(hiArr[16:], hi16)
	hiScalar := ScalarFromBytes(hiArr)

	// result = hi * 2^256 + lo mod N
	result := ScalarMul(hiScalar, two256ModN)
	result = ScalarAdd(result, loScalar)
	return result
}

// expandMsgXmd implements expand_message_xmd with SHA-256.
func expandMsgXmd(msg, dstBytes []byte, lenInBytes int) []byte {
	b := 32 // SHA-256 block size
	ell := (lenInBytes + b - 1) / b

	// DST_prime = DST || I2OSP(len(DST), 1)
	dstPrime := make([]byte, len(dstBytes)+1)
	copy(dstPrime, dstBytes)
	dstPrime[len(dstBytes)] = byte(len(dstBytes))

	// Z_pad = I2OSP(0, s)
	zPad := make([]byte, 64) // s = 64 for SHA-256

	// l_i_b_str = I2OSP(len_in_bytes, 2)
	lenBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBytes, uint16(lenInBytes))

	// msg_prime = Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime
	msgPrime := make([]byte, 0, len(zPad)+len(msg)+2+1+len(dstPrime))
	msgPrime = append(msgPrime, zPad...)
	msgPrime = append(msgPrime, msg...)
	msgPrime = append(msgPrime, lenBytes...)
	msgPrime = append(msgPrime, 0)
	msgPrime = append(msgPrime, dstPrime...)

	// b_0 = H(msg_prime)
	b0 := sha256.Sum256(msgPrime)

	// b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
	h1Input := make([]byte, 0, 32+1+len(dstPrime))
	h1Input = append(h1Input, b0[:]...)
	h1Input = append(h1Input, 1)
	h1Input = append(h1Input, dstPrime...)
	b1 := sha256.Sum256(h1Input)

	// uniform_bytes = b_1
	uniform := make([]byte, 0, lenInBytes)
	uniform = append(uniform, b1[:]...)

	// For i = 2 to ell:
	for i := 2; i <= ell; i++ {
		// b_i = H(strxor(b_0, b_(i-1)) || I2OSP(i, 1) || DST_prime)
		xor := make([]byte, 32)
		for j := range xor {
			xor[j] = b0[j] ^ uniform[len(uniform)-32+j]
		}
		hiInput := make([]byte, 0, 32+1+len(dstPrime))
		hiInput = append(hiInput, xor...)
		hiInput = append(hiInput, byte(i))
		hiInput = append(hiInput, dstPrime...)
		bi := sha256.Sum256(hiInput)
		uniform = append(uniform, bi[:]...)
	}

	return uniform[:lenInBytes]
}

// H1 computes the binding factor hash (rho).
func H1(msg []byte) [32]byte {
	s := hashToFieldN(msg, dst("rho"))
	return ScalarToBytes(s)
}

// H2 computes the challenge hash (chal).
func H2(msg []byte) [32]byte {
	s := hashToFieldN(msg, dst("chal"))
	return ScalarToBytes(s)
}

// H3 computes the nonce generation hash.
func H3(msg []byte) [32]byte {
	s := hashToFieldN(msg, dst("nonce"))
	return ScalarToBytes(s)
}

// H4 computes the message hash.
func H4(msg []byte) [32]byte {
	prefix := dst("msg")
	h := sha256.New()
	h.Write(prefix)
	h.Write(msg)
	var out [32]byte
	h.Sum(out[:0])
	return out
}

// H5 computes the commitment hash.
func H5(msg []byte) [32]byte {
	prefix := dst("com")
	h := sha256.New()
	h.Write(prefix)
	h.Write(msg)
	var out [32]byte
	h.Sum(out[:0])
	return out
}

// TagHash computes a BIP340-style tagged hash prefix.
func TagHash(tag string) [64]byte {
	h := sha256.Sum256([]byte(tag))
	var out [64]byte
	copy(out[:32], h[:])
	copy(out[32:], h[:])
	return out
}

// Hash340 computes a BIP340 tagged hash.
func Hash340(tag string, data [][]byte) [32]byte {
	prefix := TagHash(tag)
	h := sha256.New()
	h.Write(prefix[:])
	for _, d := range data {
		h.Write(d)
	}
	var out [32]byte
	h.Sum(out[:0])
	return out
}
