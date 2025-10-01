package generators

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"hash"
	"math"
	"strings"
	"sync"

	"github.com/charlielowe/uniq/pkg/common"
	"golang.org/x/crypto/ssh"
)

// SHA256 hash object pool for reuse
var sha256Pool = sync.Pool{
	New: func() interface{} {
		return sha256.New()
	},
}

// Pre-computed SSH key format constants
var (
	sshEd25519KeyType     = []byte("ssh-ed25519")
	sshEd25519KeyTypeLen  = []byte{0, 0, 0, 11} // len("ssh-ed25519")
	sshEd25519KeyDataLen  = []byte{0, 0, 0, 32} // ed25519 public key is 32 bytes
)

type Ed25519Generator struct{}

type Ed25519Result struct {
	PublicKey   ed25519.PublicKey
	PrivateKey  ed25519.PrivateKey
	Fingerprint string
}

func (r *Ed25519Result) String() string {
	return fmt.Sprintf("Found matching key pair!\nFingerprint: SHA256:%s", r.Fingerprint)
}

func (r *Ed25519Result) GetValue() string {
	return r.Fingerprint
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

func (g *Ed25519Generator) Generate() (common.Result, bool) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	fingerprint := g.calculateFingerprint(pub)

	return &Ed25519Result{
		PublicKey:   pub,
		PrivateKey:  priv,
		Fingerprint: fingerprint,
	}, true
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
	prefixBits := float64(len(prefix)) * 6
	totalCombinations := math.Pow(2, prefixBits)

	return common.ProbabilityStats{
		P75:        totalCombinations * math.Log(4),
		P99:        totalCombinations * math.Log(100),
		PrefixBits: prefixBits,
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

func (g *Ed25519Generator) calculateFingerprint(pubKey ed25519.PublicKey) string {
	// Get SHA256 hasher from pool
	h := sha256Pool.Get().(hash.Hash)
	defer func() {
		h.Reset() // Reset for reuse
		sha256Pool.Put(h)
	}()

	// SSH public key format: type_len + type + data_len + data
	h.Write(sshEd25519KeyTypeLen)
	h.Write(sshEd25519KeyType)
	h.Write(sshEd25519KeyDataLen)
	h.Write(pubKey)

	// Pre-allocate exact size buffer (SHA256 = 32 bytes)
	hashBytes := h.Sum(make([]byte, 0, 32))
	return base64.StdEncoding.EncodeToString(hashBytes)
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
