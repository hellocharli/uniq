//go:build !(darwin && arm64 && cgo)

package generators

// metalNTLM is unavailable on this platform; the CPU path is always used.
type metalNTLM struct{}

func newMetalNTLM() (*metalNTLM, error) {
	return nil, errMetalUnavailable
}

func (m *metalNTLM) free() {}

func (m *metalNTLM) search(_ uint64, _ uint32, _ uint32, _ []byte) ([][16]byte, error) {
	return nil, errMetalUnavailable
}
