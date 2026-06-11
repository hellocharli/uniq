package generators

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"hash"
	"io"
	"math"
	"strings"
	"sync"

	"github.com/charlielowe/uniq/pkg/common"
	"golang.org/x/crypto/ssh"
)

// bufferedRand serves cryptographically secure random bytes from a local
// buffer that is refilled in large chunks from crypto/rand. ed25519 key
// generation needs 32 bytes of entropy per key; reading those 32 bytes
// directly from crypto/rand.Reader on every iteration crosses the Go<->libc
// boundary (arc4random_buf on macOS) once per key, which does not scale
// across many cores (and is catastrophic across the two dies of an M-series
// Ultra). Batching the OS reads keeps full cryptographic quality (the seeds
// still come straight from the OS CSPRNG) while reducing boundary crossings
// by randBufSize/32.
const randBufSize = 16384 // 512 ed25519 seeds per OS read

type bufferedRand struct {
	buf [randBufSize]byte
	pos int
}

func (r *bufferedRand) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) {
		if r.pos >= len(r.buf) {
			if _, err := io.ReadFull(rand.Reader, r.buf[:]); err != nil {
				return n, err
			}
			r.pos = 0
		}
		c := copy(p[n:], r.buf[r.pos:])
		r.pos += c
		n += c
	}
	return n, nil
}

// edScratch bundles all per-worker reusable state for the hot loop: the
// buffered entropy reader, the SHA-256 hasher, and stack-sized scratch buffers
// for the seed, the digest, and its base64 encoding. Pooling these means a miss
// only allocates the 64-byte private key that ed25519.NewKeyFromSeed must
// return (stdlib has no public-key-only-from-seed entry point).
type edScratch struct {
	rand bufferedRand
	h    hash.Hash
	seed [32]byte
	sum  [32]byte
	b64  [44]byte // base64 of 32 bytes = 44 chars
}

// scratchPool holds per-P edScratch instances so workers don't share state.
var scratchPool = sync.Pool{
	New: func() any {
		// pos == len(buf) forces an entropy refill on first use.
		s := &edScratch{h: sha256.New()}
		s.rand.pos = randBufSize
		return s
	},
}

// Pre-computed SSH key format constants
var (
	sshEd25519KeyType    = []byte("ssh-ed25519")
	sshEd25519KeyTypeLen = []byte{0, 0, 0, 11} // len("ssh-ed25519")
	sshEd25519KeyDataLen = []byte{0, 0, 0, 32} // ed25519 public key is 32 bytes
)

type Ed25519Generator struct{}

type Ed25519Result struct {
	PublicKey   ed25519.PublicKey
	PrivateKey  ed25519.PrivateKey
	Fingerprint string
}

func (r *Ed25519Result) GetDetails() []string {
	return []string{
		fmt.Sprintf("Fingerprint : %s", r.Fingerprint),
		fmt.Sprintf("Public Key  : ssh-ed25519 %s", r.formatPublicKey()),
		r.formatPrivateKey(),
	}
}

func NewEd25519Generator() *Ed25519Generator {
	return &Ed25519Generator{}
}

func (g *Ed25519Generator) TryMatch(prefix string) (common.Result, bool) {
	s := scratchPool.Get().(*edScratch)

	// Derive the key directly from our own buffered seed. NewKeyFromSeed only
	// allocates the 64-byte private key (pub is its second half), avoiding the
	// extra seed/pub allocations that ed25519.GenerateKey performs.
	if _, err := s.rand.Read(s.seed[:]); err != nil {
		panic(err)
	}
	priv := ed25519.NewKeyFromSeed(s.seed[:])
	pub := priv[32:]

	// Compute the SSH fingerprint's SHA256 and base64-encode it into pooled
	// scratch buffers so a miss allocates nothing beyond the priv key above.
	s.h.Reset()
	s.h.Write(sshEd25519KeyTypeLen)
	s.h.Write(sshEd25519KeyType)
	s.h.Write(sshEd25519KeyDataLen)
	s.h.Write(pub)
	digest := s.h.Sum(s.sum[:0])
	base64.StdEncoding.Encode(s.b64[:], digest)

	if !hasBytePrefix(s.b64[:], prefix) {
		scratchPool.Put(s)
		return nil, false
	}

	// Match (rare): materialize the full result before returning scratch.
	res := &Ed25519Result{
		PublicKey:   ed25519.PublicKey(pub),
		PrivateKey:  priv,
		Fingerprint: string(s.b64[:]),
	}
	scratchPool.Put(s)
	return res, true
}

// hasBytePrefix reports whether b starts with prefix, without allocation.
func hasBytePrefix(b []byte, prefix string) bool {
	if len(prefix) > len(b) {
		return false
	}
	for i := 0; i < len(prefix); i++ {
		if b[i] != prefix[i] {
			return false
		}
	}
	return true
}

func (g *Ed25519Generator) ValidatePrefix(prefix string) error {
	if prefix == "" {
		return fmt.Errorf("prefix cannot be empty")
	}

	if !g.isValidBase64(prefix) {
		return fmt.Errorf("invalid prefix. Must be valid base64 characters")
	}

	return nil
}

func (g *Ed25519Generator) CalculateProbabilities(prefix string) common.ProbabilityStats {
	// Each character in base64 represents ~6 bits of entropy
	totalCombinations := math.Pow(2, float64(len(prefix))*6)

	return common.ProbabilityStats{
		P75: totalCombinations * math.Log(4),
		P99: totalCombinations * math.Log(100),
	}
}

func (g *Ed25519Generator) GetTypeName() string {
	return "Ed25519"
}

func (g *Ed25519Generator) GetMetricName() string {
	return "Keys"
}

func (g *Ed25519Generator) GetRateUnit() string {
	return "K/s"
}

func (g *Ed25519Generator) isValidBase64(s string) bool {
	// Allow base64 characters and common prefix patterns
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == '+' || r == '/') {
			return false
		}
	}
	return true
}

func (r *Ed25519Result) formatPublicKey() string {
	// Pre-allocate buffer with exact size needed
	// 4 + 11 + 4 + 32 = 51 bytes total
	keyBytes := make([]byte, 0, 51)
	keyBytes = append(keyBytes, sshEd25519KeyTypeLen...)
	keyBytes = append(keyBytes, sshEd25519KeyType...)
	keyBytes = append(keyBytes, sshEd25519KeyDataLen...)
	keyBytes = append(keyBytes, r.PublicKey...)
	return base64.StdEncoding.EncodeToString(keyBytes)
}

func (r *Ed25519Result) formatPrivateKey() string {
	// Marshal to OpenSSH format
	block, err := ssh.MarshalPrivateKey(r.PrivateKey, "1 little comment")
	if err != nil {
		panic(err)
	}
	blockString := string(pem.EncodeToMemory(block))

	return strings.TrimSuffix(blockString, "\n")
}
