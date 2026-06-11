package generators

import "testing"

// Benchmarks exercise the miss path (prefix that effectively never matches),
// which is what the hot search loop spends ~all its time in.

func BenchmarkNTLMTryMatchMiss(b *testing.B) {
	g := NewNTLMGenerator()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		g.TryMatch("FFFFFFFF")
	}
}

func BenchmarkEd25519TryMatchMiss(b *testing.B) {
	g := NewEd25519Generator()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		g.TryMatch("ZZZZZZ")
	}
}
