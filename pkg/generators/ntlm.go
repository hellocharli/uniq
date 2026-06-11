package generators

import (
	"fmt"
	"math"
	"math/bits"
	"sync"
	"sync/atomic"
	"time"

	"github.com/charlielowe/uniq/pkg/common"
)

// Custom uppercase hex encoder - avoids strings.ToUpper allocation
const hexCharsUpper = "0123456789ABCDEF"

const charsetLen = uint64(len(common.Charset))

func hexEncodeUpper(src []byte) string {
	dst := make([]byte, len(src)*2)
	for i, b := range src {
		dst[i*2] = hexCharsUpper[b>>4]
		dst[i*2+1] = hexCharsUpper[b&0x0f]
	}
	return string(dst)
}

// ntlmScratch holds per-worker reusable state for the hot loop so a candidate
// can be generated, hashed, and prefix-checked with zero heap allocations.
// Instances are pooled per-P; each is only ever used by one goroutine at a
// time (sync.Pool removes it on Get), so the non-atomic xorshift state is safe.
type ntlmScratch struct {
	state uint64   // xorshift64 PRNG state (never zero)
	pw    [16]byte // ASCII password bytes
}

// splitmix64 mixes a counter into a well-distributed 64-bit seed.
func splitmix64(x uint64) uint64 {
	x += 0x9e3779b97f4a7c15
	x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9
	x = (x ^ (x >> 27)) * 0x94d049bb133111eb
	return x ^ (x >> 31)
}

var ntlmSeedCtr atomic.Uint64

var ntlmScratchPool = sync.Pool{
	New: func() interface{} {
		seed := splitmix64(uint64(time.Now().UnixNano()) ^ ntlmSeedCtr.Add(1))
		if seed == 0 {
			seed = 0x9e3779b97f4a7c15
		}
		return &ntlmScratch{state: seed}
	},
}

// md4Block32 computes the MD4 digest of a 16-character ASCII password encoded
// as UTF-16LE (32 message bytes). Because the message length is fixed, the
// padded message is exactly one 64-byte MD4 block, so this is a fully unrolled
// single-block compression with no interface dispatch and no allocation.
//
// For ASCII char c the UTF-16LE pair is (c, 0x00); two consecutive chars pack
// into one little-endian 32-bit word as pw[2j] | pw[2j+1]<<16.
func md4Block32(pw *[16]byte) [16]byte {
	var x [16]uint32
	for j := 0; j < 8; j++ {
		x[j] = uint32(pw[2*j]) | uint32(pw[2*j+1])<<16
	}
	// x[8] holds the 0x80 padding byte; x[14] is the bit length (32 bytes =
	// 256 bits). The rest stay zero.
	x[8] = 0x80
	x[14] = 256

	const (
		a0 = 0x67452301
		b0 = 0xefcdab89
		c0 = 0x98badcfe
		d0 = 0x10325476
	)
	a, b, c, d := uint32(a0), uint32(b0), uint32(c0), uint32(d0)

	// Round 1: F(b,c,d) = (b&c)|(^b&d), shifts 3,7,11,19, k = 0..15.
	{
		shift := [4]uint{3, 7, 11, 19}
		for i := 0; i < 16; i++ {
			f := (c^d)&b ^ d
			a += f + x[i]
			a = bits.RotateLeft32(a, int(shift[i&3]))
			a, b, c, d = d, a, b, c
		}
	}
	// Round 2: G(b,c,d) = (b&c)|(b&d)|(c&d), shifts 3,5,9,13.
	{
		shift := [4]uint{3, 5, 9, 13}
		idx := [16]uint{0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15}
		for i := 0; i < 16; i++ {
			g := b&c | b&d | c&d
			a += g + x[idx[i]] + 0x5a827999
			a = bits.RotateLeft32(a, int(shift[i&3]))
			a, b, c, d = d, a, b, c
		}
	}
	// Round 3: H(b,c,d) = b^c^d, shifts 3,9,11,15.
	{
		shift := [4]uint{3, 9, 11, 15}
		idx := [16]uint{0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15}
		for i := 0; i < 16; i++ {
			h := b ^ c ^ d
			a += h + x[idx[i]] + 0x6ed9eba1
			a = bits.RotateLeft32(a, int(shift[i&3]))
			a, b, c, d = d, a, b, c
		}
	}

	a += a0
	b += b0
	c += c0
	d += d0

	var sum [16]byte
	for i, v := range [4]uint32{a, b, c, d} {
		sum[i*4] = byte(v)
		sum[i*4+1] = byte(v >> 8)
		sum[i*4+2] = byte(v >> 16)
		sum[i*4+3] = byte(v >> 24)
	}
	return sum
}

// matchNTLMPrefix reports whether the uppercase hex encoding of sum begins with
// prefix, without allocating an intermediate hex string. prefix is expected to
// be uppercase hex (the ntlm command uppercases it).
func matchNTLMPrefix(sum []byte, prefix string) bool {
	if len(prefix) > len(sum)*2 {
		return false
	}
	for i := 0; i < len(prefix); i++ {
		b := sum[i/2]
		var nib byte
		if i&1 == 0 {
			nib = b >> 4
		} else {
			nib = b & 0x0f
		}
		if hexCharsUpper[nib] != prefix[i] {
			return false
		}
	}
	return true
}

type NTLMGenerator struct{}

type NTLMResult struct {
	Password string
	Hash     string
}

func (r *NTLMResult) GetDetails() []string {
	return []string{
		fmt.Sprintf("Password  : %s", r.Password),
		fmt.Sprintf("NTLM Hash : %s", r.Hash),
	}
}

func NewNTLMGenerator() *NTLMGenerator {
	return &NTLMGenerator{}
}

func (g *NTLMGenerator) TryMatch(prefix string) (common.Result, bool) {
	s := ntlmScratchPool.Get().(*ntlmScratch)

	// Generate a random 16-char ASCII password. xorshift64 yields 64 bits per
	// step; each half maps to a charset index with Lemire's division-free
	// reduction (idx = hi32(rand32 * len)), so two chars cost one PRNG step.
	st := s.state
	for i := 0; i < 16; i += 2 {
		st ^= st << 13
		st ^= st >> 7
		st ^= st << 17
		s.pw[i] = common.Charset[(uint64(uint32(st))*charsetLen)>>32]
		s.pw[i+1] = common.Charset[(uint64(uint32(st>>32))*charsetLen)>>32]
	}
	s.state = st

	digest := md4Block32(&s.pw)

	if !matchNTLMPrefix(digest[:], prefix) {
		ntlmScratchPool.Put(s)
		return nil, false
	}

	// Match (rare): now it's worth allocating the real result.
	res := &NTLMResult{
		Password: string(s.pw[:]),
		Hash:     hexEncodeUpper(digest[:]),
	}
	ntlmScratchPool.Put(s)
	return res, true
}

func (g *NTLMGenerator) ValidatePrefix(prefix string) error {
	if prefix == "" {
		return fmt.Errorf("prefix cannot be empty")
	}

	if !g.isValidHex(prefix) {
		return fmt.Errorf("invalid prefix. Must be a hex string")
	}

	return nil
}

func (g *NTLMGenerator) CalculateProbabilities(prefix string) common.ProbabilityStats {
	totalHashes := math.Pow(2, float64(len(prefix)*4)) // 4 bits per hex character

	return common.ProbabilityStats{
		P75: totalHashes * math.Log(4),
		P99: totalHashes * math.Log(100),
	}
}

func (g *NTLMGenerator) GetTypeName() string {
	return "NTLM"
}

func (g *NTLMGenerator) GetMetricName() string {
	return "Hashes"
}

func (g *NTLMGenerator) GetRateUnit() string {
	return "H/s"
}

func (g *NTLMGenerator) isValidHex(s string) bool {
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}
