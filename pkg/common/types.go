package common

import (
	"context"
	"sync/atomic"
	"time"
)

// Generator defines the interface for different key/hash generators
type Generator interface {
	// Generate creates a new instance and checks if it matches the prefix
	Generate() (Result, bool)

	// ValidatePrefix checks if the prefix is valid for this generator type
	ValidatePrefix(prefix string) error

	// CalculateProbabilities returns probability metrics for the given prefix
	CalculateProbabilities(prefix string) ProbabilityStats

	// GetTypeName returns the human-readable name of the generator type
	GetTypeName() string

	// GetMetricName returns the metric name (e.g., "Hashes", "Keys", "Attempts")
	GetMetricName() string

	// GetRateUnit returns the rate unit (e.g., "H/s", "Keys/s")
	GetRateUnit() string
}

// Result represents a generated key/hash result
type Result interface {
	// String returns a human-readable representation
	String() string

	// GetValue returns the main value (hash, fingerprint, etc.)
	GetValue() string

	// GetDetails returns additional details to display
	GetDetails() []string
}

// FoundResult represents a result with timing information
type FoundResult struct {
	Result    Result
	FoundAt   time.Time
	Attempts  int64
}

// ProbabilityStats contains probability calculations
type ProbabilityStats struct {
	P75         float64 // 75% probability
	P99         float64 // 99% probability
	PrefixBits  float64 // Bits of entropy in prefix
}

// MultiStats holds runtime statistics for multiple result searches
type MultiStats struct {
	Attempts         *atomic.Int64
	StartTime        time.Time
	CurrentSearch    *atomic.Int32    // Which result we're currently searching for (1-based)
	TotalTargets     int              // Total number of results to find
	FoundResults     []FoundResult    // Results found so far
	Context          context.Context
	Cancel           context.CancelFunc
	CurrentStartTime time.Time        // Start time for current search
	CurrentAttempts  *atomic.Int64    // Attempts for current search only
}

// Stats holds runtime statistics (kept for backward compatibility)
type Stats struct {
	Attempts      *atomic.Int64
	StartTime     time.Time
	Found         *atomic.Value // stores Result when found
	Context       context.Context
	Cancel        context.CancelFunc
}

// NewMultiStats creates a new MultiStats instance
func NewMultiStats(totalTargets int) *MultiStats {
	ctx, cancel := context.WithCancel(context.Background())
	now := time.Now()
	return &MultiStats{
		Attempts:         &atomic.Int64{},
		StartTime:        now,
		CurrentSearch:    &atomic.Int32{},
		TotalTargets:     totalTargets,
		FoundResults:     make([]FoundResult, 0, totalTargets),
		Context:          ctx,
		Cancel:           cancel,
		CurrentStartTime: now,
		CurrentAttempts:  &atomic.Int64{},
	}
}

// NewStats creates a new Stats instance
func NewStats() *Stats {
	ctx, cancel := context.WithCancel(context.Background())
	return &Stats{
		Attempts:  &atomic.Int64{},
		StartTime: time.Now(),
		Found:     &atomic.Value{},
		Context:   ctx,
		Cancel:    cancel,
	}
}

// AddResult adds a found result and resets counters for next search
func (ms *MultiStats) AddResult(result Result) {
	foundResult := FoundResult{
		Result:   result,
		FoundAt:  time.Now(),
		Attempts: ms.CurrentAttempts.Load(),
	}

	ms.FoundResults = append(ms.FoundResults, foundResult)

	// Start looking for next result (only if we need more)
	if len(ms.FoundResults) < ms.TotalTargets {
		ms.CurrentSearch.Add(1)
		ms.CurrentStartTime = time.Now()
		ms.CurrentAttempts.Store(0)
	}
}

// GetCurrentSearch returns which result we're currently searching for (1-based)
func (ms *MultiStats) GetCurrentSearch() int {
	return int(ms.CurrentSearch.Load()) + 1
}

// IsComplete returns true if we've found all target results
func (ms *MultiStats) IsComplete() bool {
	return len(ms.FoundResults) >= ms.TotalTargets
}