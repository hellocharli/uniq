//go:build darwin && arm64 && cgo

package generators

import (
	"sort"
	"testing"

	"github.com/charlielowe/uniq/pkg/common"
)

// genCandidate reproduces the Metal kernel's per-(gid,iter) candidate exactly:
// splitmix64 seed from base+gid, then xorshift64 advanced `it+1` times (each
// producing 16 chars). Returns the password after the (it)-th generation.
func genCandidate(base uint64, gid, it uint32) [16]byte {
	st := splitmix64(base + uint64(gid))
	if st == 0 {
		st = 0x9e3779b97f4a7c15
	}
	var pw [16]byte
	for k := uint32(0); k <= it; k++ {
		for i := 0; i < 16; i += 2 {
			st ^= st << 13
			st ^= st >> 7
			st ^= st << 17
			pw[i] = common.Charset[(uint64(uint32(st))*charsetLen)>>32]
			pw[i+1] = common.Charset[(uint64(uint32(st>>32))*charsetLen)>>32]
		}
	}
	return pw
}

// TestMetalMatchesCPU asserts the GPU kernel finds exactly the same matches the
// CPU code would for the identical candidate stream.
func TestMetalMatchesCPU(t *testing.T) {
	m, err := newMetalNTLM()
	if err != nil {
		t.Skipf("metal unavailable: %v", err)
	}
	defer m.free()

	const (
		base    = uint64(0x1234567890abcdef)
		threads = uint32(65536)
		iters   = uint32(8)
	)
	prefix := "ABC" // 3 nibbles => ~1/4096 hit rate, ~128 expected hits < cap

	nibbles := prefixToNibbles(prefix)

	// Expected matches per the CPU implementation.
	expected := map[string]bool{}
	for gid := uint32(0); gid < threads; gid++ {
		for it := uint32(0); it < iters; it++ {
			pw := genCandidate(base, gid, it)
			digest := md4Block32(&pw)
			if matchNTLMPrefix(digest[:], prefix) {
				expected[string(pw[:])] = true
			}
		}
	}
	if len(expected) == 0 {
		t.Fatal("no expected matches; adjust test params")
	}
	if len(expected) > metalMaxHits {
		t.Fatalf("expected %d matches exceeds cap %d; lengthen prefix", len(expected), metalMaxHits)
	}

	pws, err := m.search(base, threads, iters, nibbles)
	if err != nil {
		t.Fatalf("search: %v", err)
	}

	got := map[string]bool{}
	for _, pw := range pws {
		// Every returned password must genuinely match under the CPU MD4.
		digest := md4Block32(&pw)
		if !matchNTLMPrefix(digest[:], prefix) {
			t.Errorf("GPU returned non-matching password %q (hash %s)", pw[:], hexEncodeUpper(digest[:]))
		}
		got[string(pw[:])] = true
	}

	if len(got) != len(expected) {
		t.Errorf("match count mismatch: GPU=%d CPU=%d", len(got), len(expected))
	}
	for pw := range expected {
		if !got[pw] {
			t.Errorf("CPU match missing from GPU results: %q", pw)
		}
	}
	for pw := range got {
		if !expected[pw] {
			t.Errorf("GPU match not predicted by CPU: %q", pw)
		}
	}

	if t.Failed() {
		// Dump a few for debugging.
		var e, g []string
		for pw := range expected {
			e = append(e, pw)
		}
		for pw := range got {
			g = append(g, pw)
		}
		sort.Strings(e)
		sort.Strings(g)
		t.Logf("expected(%d): %v", len(e), e[:min(5, len(e))])
		t.Logf("got(%d): %v", len(g), g[:min(5, len(g))])
	}
}
