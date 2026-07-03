//go:build darwin && arm64 && cgo

package generators

/*
#cgo LDFLAGS: -framework Foundation -framework Metal
#include <stdlib.h>
#include "metal_ntlm.h"
*/
import "C"

import (
	"fmt"
	"unsafe"

	"github.com/charlielowe/uniq/pkg/common"
)

// metalMaxHits caps how many matches a single dispatch will record. A batch
// searching for a real prefix produces at most a handful; extras are counted
// but not written back.
const metalMaxHits = 256

// metalNTLM wraps the Objective-C Metal engine.
type metalNTLM struct {
	h      *C.ntlm_metal
	outBuf [metalMaxHits * 16]byte
}

func newMetalNTLM() (*metalNTLM, error) {
	cs := C.CString(common.Charset)
	defer C.free(unsafe.Pointer(cs))

	var errbuf [256]C.char
	h := C.ntlm_metal_new(cs, C.int(len(common.Charset)), C.int(metalMaxHits),
		&errbuf[0], C.int(len(errbuf)))
	if h == nil {
		return nil, fmt.Errorf("metal init: %s", C.GoString(&errbuf[0]))
	}
	return &metalNTLM{h: h}, nil
}

func (m *metalNTLM) free() {
	if m.h != nil {
		C.ntlm_metal_free(m.h)
		m.h = nil
	}
}

// search runs one dispatch of threads*iters candidates seeded from base and
// returns the matching 16-byte passwords. tried is threads*iters.
func (m *metalNTLM) search(base uint64, threads, iters uint32, prefixNibbles []byte) (pws [][16]byte, err error) {
	n := C.ntlm_metal_search(m.h, C.uint64_t(base), C.uint32_t(threads), C.uint32_t(iters),
		(*C.uint8_t)(unsafe.Pointer(&prefixNibbles[0])), C.int(len(prefixNibbles)),
		(*C.uint8_t)(unsafe.Pointer(&m.outBuf[0])))
	if n < 0 {
		return nil, fmt.Errorf("metal search failed")
	}
	hits := int(n)
	if hits > metalMaxHits {
		hits = metalMaxHits
	}
	pws = make([][16]byte, hits)
	for i := 0; i < hits; i++ {
		copy(pws[i][:], m.outBuf[i*16:i*16+16])
	}
	return pws, nil
}
