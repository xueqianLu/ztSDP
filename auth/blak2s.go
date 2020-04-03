package auth

import (
	"bytes"
	"golang.org/x/crypto/blake2s"
)

func BytesXor(a, b []byte) []byte {
	if (len(a) != len(b)) || (len(a) == 0) {
		return nil
	}
	c := make([]byte, len(a))
	for i := 0; i < len(a); i++ {
		c[i] = a[i] ^ b[i]
	}
	return c
}

func BytesCombine(pBytes ...[]byte) []byte {
	return bytes.Join(pBytes, []byte(""))
}

func AppidCheckVal(id, random []byte) []byte {
	b1 := BytesXor(id[0:16], random)
	b2 := BytesXor(id[16:], random)
	b := BytesCombine(b1, b2)
	h, _ := blake2s.New256(nil)
	h.Write(b)
	hash := h.Sum(nil)
	return hash
}

func UserIdCheckVal(uid, iv, random []byte) []byte {
	c := make([]byte, len(random))
	for i := 0; i < len(random); i++ {
		c[i] = uid[i] ^ iv[i] ^ random[i]
	}
	h, _ := blake2s.New256(nil)
	h.Write(c)
	hash := h.Sum(nil)
	return hash
}
