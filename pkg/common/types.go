package common

import (
	"context"
	"sync/atomic"
	"time"
)

// Generator defines the interface for different key/hash generators
type Generator interface {
	// TryMatch generates one candidate and reports whether it matches prefix.
	// On a match it returns a fully-built Result; on a miss it returns
	// (nil, false) and avoids heap allocations to minimize GC pressure in
	// the hot search loop.
	TryMatch(prefix string) (Result, bool)

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

// BatchSearcher is an optional capability a Generator can implement to run
// trials in large batches (e.g. on a GPU) instead of one candidate at a time.
// When a Generator also implements BatchSearcher, the runner drives it with a
// single batch loop rather than per-core TryMatch goroutines.
type BatchSearcher interface {
	// SearchBatch runs one batch of trials for prefix and returns any matching
	// results plus the number of candidates tried in the batch.
	SearchBatch(prefix string) (results []Result, tried int64, err error)

	// Close releases any resources held by the searcher.
	Close()
}

// Result represents a generated key/hash result
type Result interface {
	// GetDetails returns additional details to display
	GetDetails() []string
}

// FoundResult represents a result with timing information
type FoundResult struct {
	Result   Result
	Attempts int64
	Elapsed  time.Duration // wall-clock time to find this result
}

// ProbabilityStats contains probability calculations
type ProbabilityStats struct {
	P75 float64 // 75% probability
	P99 float64 // 99% probability
}

// MultiStats holds runtime statistics for multiple result searches
type MultiStats struct {
	Attempts         *atomic.Int64
	StartTime        time.Time
	TotalTargets     int           // Total number of results to find
	FoundResults     []FoundResult // Results found so far
	Context          context.Context
	Cancel           context.CancelFunc
	CurrentStartTime time.Time     // Start time for current search
	CurrentAttempts  *atomic.Int64 // Attempts for current search only
}

// Stats holds runtime statistics (kept for backward compatibility)
type Stats struct {
	Attempts  *atomic.Int64
	StartTime time.Time
	Context   context.Context
	Cancel    context.CancelFunc
}

// NewMultiStats creates a new MultiStats instance
func NewMultiStats(totalTargets int) *MultiStats {
	ctx, cancel := context.WithCancel(context.Background())
	now := time.Now()
	return &MultiStats{
		Attempts:         &atomic.Int64{},
		StartTime:        now,
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
		Context:   ctx,
		Cancel:    cancel,
	}
}

// AddResult adds a found result and resets counters for next search
func (ms *MultiStats) AddResult(result Result) {
	foundResult := FoundResult{
		Result:   result,
		Attempts: ms.CurrentAttempts.Load(),
		Elapsed:  time.Since(ms.CurrentStartTime),
	}

	ms.FoundResults = append(ms.FoundResults, foundResult)

	// Start looking for next result (only if we need more)
	if len(ms.FoundResults) < ms.TotalTargets {
		ms.CurrentStartTime = time.Now()
		ms.CurrentAttempts.Store(0)
	}
}

// IsComplete returns true if we've found all target results
func (ms *MultiStats) IsComplete() bool {
	return len(ms.FoundResults) >= ms.TotalTargets
}
