package generators

import (
	"fmt"
	"hash"
	"math"
	"math/rand"
	"runtime"
	"sync"
	"time"

	"golang.org/x/crypto/md4"

	"github.com/charlielowe/uniq/pkg/common"
)

// Custom uppercase hex encoder - avoids strings.ToUpper allocation
const hexCharsUpper = "0123456789ABCDEF"

func hexEncodeUpper(src []byte) string {
	dst := make([]byte, len(src)*2)
	for i, b := range src {
		dst[i*2] = hexCharsUpper[b>>4]
		dst[i*2+1] = hexCharsUpper[b&0x0f]
	}
	return string(dst)
}

// ntlmScratch holds all per-worker reusable state for the hot loop so that a
// candidate can be generated, hashed, and prefix-checked with zero heap
// allocations. Instances are pooled per-P; each is only ever used by one
// goroutine at a time (sync.Pool removes it on Get), so the non-concurrent
// *rand.Rand and hasher are safe.
type ntlmScratch struct {
	rng    *rand.Rand
	hasher hash.Hash
	pw     [16]byte // ASCII password bytes
	u16    [32]byte // UTF-16LE of pw; odd (high) bytes stay zero for ASCII
}

var ntlmScratchPool = sync.Pool{
	New: func() interface{} {
		return &ntlmScratch{
			rng:    rand.New(rand.NewSource(time.Now().UnixNano() + int64(runtime.NumGoroutine()))),
			hasher: md4.New(),
		}
	},
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

func (r *NTLMResult) String() string {
	return fmt.Sprintf("Found password: %s", r.Password)
}

func (r *NTLMResult) GetValue() string {
	return r.Hash
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

	// Random 16-char ASCII password directly into the scratch buffer.
	for i := range s.pw {
		s.pw[i] = common.Charset[s.rng.Intn(len(common.Charset))]
	}

	// UTF-16LE encoding: for ASCII each byte maps to (byte, 0x00). The odd
	// (high) bytes of u16 are never written and remain zero.
	for i := 0; i < len(s.pw); i++ {
		s.u16[i*2] = s.pw[i]
	}

	s.hasher.Reset()
	s.hasher.Write(s.u16[:])
	var sum [16]byte
	digest := s.hasher.Sum(sum[:0])

	if !matchNTLMPrefix(digest, prefix) {
		ntlmScratchPool.Put(s)
		return nil, false
	}

	// Match (rare): now it's worth allocating the real result.
	res := &NTLMResult{
		Password: string(s.pw[:]),
		Hash:     hexEncodeUpper(digest),
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
	prefixBits := float64(len(prefix) * 4) // 4 bits per hex character
	totalHashes := math.Pow(2, prefixBits)

	return common.ProbabilityStats{
		P75:        totalHashes * math.Log(4),
		P99:        totalHashes * math.Log(100),
		PrefixBits: prefixBits,
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
