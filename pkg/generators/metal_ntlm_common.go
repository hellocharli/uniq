package generators

import (
	"errors"
	"time"

	"github.com/charlielowe/uniq/pkg/common"
)

// Metal batch sizing. ~67M candidates per dispatch (~5ms on an M4 Max) sits
// near peak GPU throughput while keeping dispatch latency low enough for
// responsive stats updates and cancellation.
const (
	metalBatchThreads = 1 << 20
	metalBatchIters   = 64
)

// errMetalUnavailable is returned when the Metal NTLM engine cannot be used
// (unsupported platform, cgo disabled, or no GPU).
var errMetalUnavailable = errors.New("metal NTLM engine unavailable")

// MetalNTLMGenerator is an NTLM generator backed by the Metal GPU engine. It
// embeds NTLMGenerator for all metadata/validation behaviour and adds the
// BatchSearcher capability so the runner drives it in GPU-sized batches.
type MetalNTLMGenerator struct {
	NTLMGenerator
	engine *metalNTLM
	base   uint64
}

// NewMetalNTLMGenerator constructs a GPU-backed NTLM generator, or returns an
// error if Metal is unavailable on this host.
func NewMetalNTLMGenerator() (*MetalNTLMGenerator, error) {
	engine, err := newMetalNTLM()
	if err != nil {
		return nil, err
	}
	return &MetalNTLMGenerator{engine: engine, base: uint64(time.Now().UnixNano())}, nil
}

// Close releases GPU resources.
func (g *MetalNTLMGenerator) Close() { g.engine.free() }

// SearchBatch dispatches one GPU batch and materializes any matches.
func (g *MetalNTLMGenerator) SearchBatch(prefix string) ([]common.Result, int64, error) {
	nibbles := prefixToNibbles(prefix)
	pws, err := g.engine.search(g.base, metalBatchThreads, metalBatchIters, nibbles)
	g.base += metalBatchThreads // distinct seed range for the next dispatch
	tried := int64(metalBatchThreads) * int64(metalBatchIters)
	if err != nil {
		return nil, tried, err
	}
	results := make([]common.Result, len(pws))
	for i := range pws {
		digest := md4Block32(&pws[i])
		results[i] = &NTLMResult{
			Password: string(pws[i][:]),
			Hash:     hexEncodeUpper(digest[:]),
		}
	}
	return results, tried, nil
}

// prefixToNibbles converts an uppercase hex prefix into its nibble values
// (0-15), the form the Metal kernel compares against.
func prefixToNibbles(prefix string) []byte {
	nib := make([]byte, len(prefix))
	for i := 0; i < len(prefix); i++ {
		c := prefix[i]
		switch {
		case c >= '0' && c <= '9':
			nib[i] = c - '0'
		case c >= 'A' && c <= 'F':
			nib[i] = c - 'A' + 10
		case c >= 'a' && c <= 'f':
			nib[i] = c - 'a' + 10
		}
	}
	return nib
}
