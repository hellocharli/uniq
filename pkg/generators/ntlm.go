package generators

import (
	"fmt"
	"hash"
	"math"
	"sync"
	"unicode/utf16"

	"golang.org/x/crypto/md4"

	"github.com/charlielowe/uniq/pkg/common"
)

// MD4 hash object pool for reuse
var md4Pool = sync.Pool{
	New: func() interface{} {
		return md4.New()
	},
}

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

func (g *NTLMGenerator) Generate() (common.Result, bool) {
	password := common.GenerateRandomString(16)
	hash := g.ntlmHash(password)
	return &NTLMResult{
		Password: password,
		Hash:     hash,
	}, true
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

func (g *NTLMGenerator) ntlmHash(password string) string {
	// Get MD4 hasher from pool
	h := md4Pool.Get().(hash.Hash)
	defer func() {
		h.Reset() // Reset for reuse
		md4Pool.Put(h)
	}()

	utf16Password := utf16.Encode([]rune(password))

	// Write UTF-16 bytes directly without additional allocations
	for _, r := range utf16Password {
		// Write little-endian directly to avoid buffer allocation
		h.Write([]byte{byte(r), byte(r >> 8)})
	}

	// Pre-allocate exact size buffer (MD4 = 16 bytes)
	hashBytes := h.Sum(make([]byte, 0, 16))
	return hexEncodeUpper(hashBytes)
}
