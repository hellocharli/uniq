//go:build darwin && arm64 && cgo

package generators

import (
	"testing"
	"time"
)

// BenchmarkMetalThroughput measures raw candidate throughput of the Metal
// engine using a prefix that effectively never matches.
func BenchmarkMetalThroughput(b *testing.B) {
	m, err := newMetalNTLM()
	if err != nil {
		b.Skipf("metal unavailable: %v", err)
	}
	defer m.free()

	nibbles := prefixToNibbles("FFFFFFFF")

	for _, cfg := range []struct {
		threads, iters uint32
	}{
		{1 << 18, 16},
		{1 << 20, 16},
		{1 << 20, 64},
		{1 << 20, 256},
		{1 << 22, 64},
	} {
		name := fmtCfg(cfg.threads, cfg.iters)
		b.Run(name, func(b *testing.B) {
			base := uint64(1)
			// Warm up one dispatch (first launch pays scheduling setup).
			m.search(base, cfg.threads, cfg.iters, nibbles)

			start := time.Now()
			var total uint64
			for i := 0; i < b.N; i++ {
				if _, err := m.search(base, cfg.threads, cfg.iters, nibbles); err != nil {
					b.Fatal(err)
				}
				base += uint64(cfg.threads)
				total += uint64(cfg.threads) * uint64(cfg.iters)
			}
			elapsed := time.Since(start)
			b.ReportMetric(float64(total)/elapsed.Seconds()/1e6, "MH/s")
		})
	}
}

func fmtCfg(threads, iters uint32) string {
	return "t" + itoa(threads) + "_i" + itoa(iters)
}

func itoa(v uint32) string {
	if v == 0 {
		return "0"
	}
	var buf [12]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}
