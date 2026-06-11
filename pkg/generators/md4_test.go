package generators

import (
	"bytes"
	"testing"

	"golang.org/x/crypto/md4"
)

// reference NTLM hash via the same path the old implementation used.
func refNTLM(pw [16]byte) [16]byte {
	var u16 [32]byte
	for i := range(16) {
		u16[i*2] = pw[i]
	}
	h := md4.New()
	h.Write(u16[:])
	var out [16]byte
	copy(out[:], h.Sum(nil))
	return out
}

func TestMD4Block32MatchesReference(t *testing.T) {
	g := NewNTLMGenerator()
	s := ntlmScratchPool.Get().(*ntlmScratch)
	defer ntlmScratchPool.Put(s)
	for range 10000 {
		st := s.state
		for i := 0; i < 16; i += 2 {
			st ^= st << 13
			st ^= st >> 7
			st ^= st << 17
			s.pw[i] = charsetByte(uint32(st))
			s.pw[i+1] = charsetByte(uint32(st >> 32))
		}
		s.state = st

		got := md4Block32(&s.pw)
		want := refNTLM(s.pw)
		if !bytes.Equal(got[:], want[:]) {
			t.Fatalf("md4 mismatch for %q: got %x want %x", s.pw, got, want)
		}
	}
	_ = g
}

func charsetByte(r uint32) byte {
	return charsetBytes[(uint64(r)*charsetLen)>>32]
}

var charsetBytes = []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
