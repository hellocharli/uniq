package common

import (
	"math/rand"
	"runtime"
	"sync"
	"time"
)

const Charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// ANSI color codes
const (
	ColorReset = "\033[0m"
	ColorRed   = "\033[31m"
	ColorGreen = "\033[32m"
)

// Thread-local fast PRNG pool for high-performance random string generation
var rngPool = sync.Pool{
	New: func() interface{} {
		// Create a unique seed for each goroutine
		seed := time.Now().UnixNano() + int64(runtime.NumGoroutine())
		return rand.New(rand.NewSource(seed))
	},
}

// GenerateRandomString creates a random string from the charset using fast PRNG
func GenerateRandomString(length int) string {
	rng := rngPool.Get().(*rand.Rand)
	defer rngPool.Put(rng)

	b := make([]byte, length)
	for i := 0; i < length; i++ {
		b[i] = Charset[rng.Intn(len(Charset))]
	}
	return string(b)
}