package cmd

import (
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/charlielowe/uniq/pkg/common"
	"github.com/charlielowe/uniq/pkg/ui"
)

func runGenerator(generator common.Generator, prefix string, numResults int) {
	// Validate prefix
	if err := generator.ValidatePrefix(prefix); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	// Format the proper singular/plural form
	var typeName string
	if numResults == 1 {
		if generator.GetTypeName() == "Ed25519" {
			typeName = "key"
		} else {
			typeName = "hash"
		}
	} else {
		if generator.GetTypeName() == "Ed25519" {
			typeName = "keys"
		} else {
			typeName = "hashes"
		}
	}

	fmt.Printf("Searching for %d %s %s with prefix: %s\n", numResults, generator.GetTypeName(), typeName, prefix)

	if numResults == 1 {
		// Use original single-result search for better performance
		results := runSingleSearch(generator, prefix)
		ui.PrintResults(results, generator, len(results) == 0)
	} else {
		// Use enhanced multi-result search
		foundResults := runMultiSearch(generator, prefix, numResults)
		ui.PrintMultiResults(foundResults, generator, len(foundResults) == 0)
	}
}

func runSingleSearch(generator common.Generator, prefix string) []common.Result {
	stats := common.NewStats()
	var results []common.Result
	var resultsMutex sync.Mutex

	numCPU := runtime.NumCPU()
	runtime.GOMAXPROCS(numCPU)

	// Handle interrupts
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
		<-c
		stats.Cancel()
	}()

	var wg sync.WaitGroup

	// Use buffered channel to reduce contention
	found := make(chan common.Result, 1)

	// Start worker goroutines with batching to reduce context switching
	for range numCPU {
		wg.Add(1)
		go func() {
			defer wg.Done()
			const batchSize = 1000 // Process in batches to reduce cancellation checks

			for {
				// Check cancellation less frequently for better performance
				select {
				case <-stats.Context.Done():
					return
				default:
				}

				// Process a batch of generations
				for batch := 0; batch < batchSize; batch++ {
					result, matches := generator.Generate()
					stats.Attempts.Add(1)

					if matches && strings.HasPrefix(result.GetValue(), prefix) {
						// Try to send result, exit if already found
						select {
						case found <- result:
							stats.Cancel()
							return
						default:
							return // Another goroutine already found it
						}
					}
				}
			}
		}()
	}

	// Result collection goroutine
	go func() {
		select {
		case result := <-found:
			resultsMutex.Lock()
			results = append(results, result)
			resultsMutex.Unlock()
		case <-stats.Context.Done():
		}
	}()

	// Stats rendering loop
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	// Reserve 3 lines for stats
	fmt.Print("\n\n\n")

statsLoop:
	for {
		select {
		case <-stats.Context.Done():
			break statsLoop
		case <-ticker.C:
			ui.PrintStats(stats, generator, prefix)
		}
	}

	// Final stats print
	ui.PrintStats(stats, generator, prefix)

	wg.Wait()

	return results
}

func runMultiSearch(generator common.Generator, prefix string, numResults int) []common.FoundResult {
	multiStats := common.NewMultiStats(numResults)
	var resultsMutex sync.Mutex

	numCPU := runtime.NumCPU()
	runtime.GOMAXPROCS(numCPU)

	// Handle interrupts
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
		<-c
		multiStats.Cancel()
	}()

	var wg sync.WaitGroup

	// Start worker goroutines with batching
	for i := 0; i < numCPU; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			const batchSize = 1000 // Process in batches

			for {
				// Check cancellation less frequently
				select {
				case <-multiStats.Context.Done():
					return
				default:
				}

				// Process a batch of generations
				for batch := 0; batch < batchSize; batch++ {
					result, matches := generator.Generate()
					multiStats.Attempts.Add(1)
					multiStats.CurrentAttempts.Add(1)

					if matches && strings.HasPrefix(result.GetValue(), prefix) {
						resultsMutex.Lock()
						if !multiStats.IsComplete() {
							multiStats.AddResult(result)

							if multiStats.IsComplete() {
								multiStats.Cancel()
								resultsMutex.Unlock()
								return
							}
						}
						resultsMutex.Unlock()
					}
				}
			}
		}()
	}

	// Stats rendering loop
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	// Reserve 4 lines for enhanced stats
	fmt.Print("\n\n\n\n")

statsLoop:
	for {
		select {
		case <-multiStats.Context.Done():
			break statsLoop
		case <-ticker.C:
			ui.PrintMultiStats(multiStats, generator, prefix)
		}
	}

	// Final stats print
	ui.PrintMultiStats(multiStats, generator, prefix)

	wg.Wait()

	return multiStats.FoundResults
}