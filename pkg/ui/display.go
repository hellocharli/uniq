package ui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charlielowe/uniq/pkg/common"
)

// PrintStats renders the TUI with progress bar and statistics
func PrintStats(stats *common.Stats, generator common.Generator, prefix string) {
	// Move cursor up 3 lines and to the start of the line
	fmt.Print("\r\033[3A")

	attempts := stats.Attempts.Load()
	elapsed := time.Since(stats.StartTime)

	var attemptsPerSecond float64
	if elapsed.Seconds() > 0 {
		attemptsPerSecond = float64(attempts) / elapsed.Seconds()
	}

	probStats := generator.CalculateProbabilities(prefix)

	var timeTo75Str string
	if attemptsPerSecond > 0 {
		timeTo75 := time.Duration(probStats.P75/attemptsPerSecond) * time.Second
		timeTo75Str = timeTo75.Round(time.Second).String()
	} else {
		timeTo75Str = "..."
	}

	var progress float64
	if probStats.P75 > 0 {
		progress = (float64(attempts) / probStats.P75) * 100
	}
	if progress > 100 {
		progress = 100
	}

	// Create progress bar with 50 block characters
	filledBlocks := int(progress / 2) // progress / 100 * 50
	progressBar := strings.Repeat("█", filledBlocks) + strings.Repeat(" ", 50-filledBlocks)

	clearLine := "\033[K"

	// Format the left portions of each line
	line1Left := fmt.Sprintf("%s: %d", generator.GetMetricName(), attempts)
	line2Left := fmt.Sprintf("P99: %.0f", probStats.P99)

	// Find the maximum length to align the vertical bars
	maxLeftLen := len(line1Left)
	if len(line2Left) > maxLeftLen {
		maxLeftLen = len(line2Left)
	}

	// Pad each line to align the vertical bars
	line1Left = fmt.Sprintf("%-*s", maxLeftLen, line1Left)
	line2Left = fmt.Sprintf("%-*s", maxLeftLen, line2Left)

	// 3-line output with aligned vertical bars
	fmt.Printf("%s%s │ %s: %.0f\n", clearLine, line1Left, generator.GetRateUnit(), attemptsPerSecond)
	fmt.Printf("%s%s │ ETA (75%%): %s\n", clearLine, line2Left, timeTo75Str)
	fmt.Printf("%s│%s│ %s\n", clearLine, progressBar, elapsed.Round(time.Second).String())
}

// PrintMultiStats renders the enhanced TUI for multiple result searches
func PrintMultiStats(multiStats *common.MultiStats, generator common.Generator, prefix string) {
	// Move cursor up 4 lines and to the start of the line
	fmt.Print("\r\033[4A")

	currentAttempts := multiStats.CurrentAttempts.Load()
	totalAttempts := multiStats.Attempts.Load()
	currentElapsed := time.Since(multiStats.CurrentStartTime)
	totalElapsed := time.Since(multiStats.StartTime)

	var currentRate float64
	if currentElapsed.Seconds() > 0 {
		currentRate = float64(currentAttempts) / currentElapsed.Seconds()
	}

	probStats := generator.CalculateProbabilities(prefix)

	var timeTo75Str string
	if currentRate > 0 {
		timeTo75 := time.Duration(probStats.P75/currentRate) * time.Second
		timeTo75Str = timeTo75.Round(time.Second).String()
	} else {
		timeTo75Str = "..."
	}

	var progress float64
	if probStats.P75 > 0 {
		progress = (float64(currentAttempts) / probStats.P75) * 100
	}
	if progress > 100 {
		progress = 100
	}

	// Create progress bar with 50 block characters
	filledBlocks := int(progress / 2)
	progressBar := strings.Repeat("█", filledBlocks) + strings.Repeat(" ", 50-filledBlocks)

	clearLine := "\033[K"

	// Progress indicator for the progress bar
	foundCount := len(multiStats.FoundResults)

	// Format the left portions of each line
	line1Left := fmt.Sprintf("Total %s: %d", generator.GetMetricName(), totalAttempts)
	line2Left := fmt.Sprintf("P99: %.0f", probStats.P99)
	line3Left := fmt.Sprintf("Current %s: %d", generator.GetMetricName(), currentAttempts)

	// Find the maximum length to align the vertical bars
	maxLeftLen := len(line1Left)
	lengths := []int{len(line2Left), len(line3Left)}
	for _, l := range lengths {
		if l > maxLeftLen {
			maxLeftLen = l
		}
	}

	// Pad each line to align the vertical bars
	line1Left = fmt.Sprintf("%-*s", maxLeftLen, line1Left)
	line2Left = fmt.Sprintf("%-*s", maxLeftLen, line2Left)
	line3Left = fmt.Sprintf("%-*s", maxLeftLen, line3Left)

	// 4-line output with aligned vertical bars
	fmt.Printf("%s%s │ %s: %.0f\n", clearLine, line1Left, generator.GetRateUnit(), func() float64 {
		if totalElapsed.Seconds() > 0 {
			return float64(totalAttempts) / totalElapsed.Seconds()
		}
		return 0
	}())
	fmt.Printf("%s%s │ ETA (75%%): %s\n", clearLine, line2Left, timeTo75Str)
	fmt.Printf("%s%s │ Current Time: %s\n", clearLine, line3Left, currentElapsed.Round(time.Second).String())
	fmt.Printf("%s│%s│ Found %d/%d in %s\n", clearLine, progressBar, foundCount, multiStats.TotalTargets, totalElapsed.Round(time.Second).String())
}

// PrintResults displays the final results
func PrintResults(results []common.Result, generator common.Generator, cancelled bool) {
	if cancelled {
		fmt.Printf("\n%sSearch cancelled.%s\n", common.ColorRed, common.ColorReset)
		return
	}

	if len(results) == 0 {
		fmt.Printf("\n%sNo results found.%s\n", common.ColorRed, common.ColorReset)
		return
	}

	fmt.Printf("\n")

	for _, result := range results {
		details := result.GetDetails()
		for _, detail := range details {
			fmt.Printf("%s%s%s\n", common.ColorGreen, detail, common.ColorReset)
		}
	}
}

// PrintMultiResults displays results with timing information
func PrintMultiResults(foundResults []common.FoundResult, generator common.Generator, cancelled bool) {
	if cancelled {
		fmt.Printf("\n%sSearch cancelled.%s\n", common.ColorRed, common.ColorReset)
		return
	}

	if len(foundResults) == 0 {
		fmt.Printf("\n%sNo results found.%s\n", common.ColorRed, common.ColorReset)
		return
	}

	fmt.Printf("\n")

	for i, foundResult := range foundResults {
		// Calculate elapsed time
		elapsed := time.Duration(foundResult.Attempts) * time.Microsecond
		if elapsed < time.Millisecond {
			elapsed = time.Millisecond
		}

		// Format time in a human readable way
		var timeStr string
		if elapsed < time.Second {
			timeStr = fmt.Sprintf("%.0fms", elapsed.Seconds()*1000)
		} else if elapsed < time.Minute {
			timeStr = fmt.Sprintf("%.1fs", elapsed.Seconds())
		} else {
			timeStr = elapsed.Round(time.Second).String()
		}

		// Show when this result was found and how many attempts it took
		fmt.Printf("%s[%d] %d attempts in %s%s\n",
			common.ColorGreen,
			i+1,
			foundResult.Attempts,
			timeStr,
			common.ColorReset)

		// Get the result details and display them
		details := foundResult.Result.GetDetails()
		for _, detail := range details {
			fmt.Printf("%s%s%s\n", common.ColorGreen, detail, common.ColorReset)
		}

		// Only add newline if not the last result
		if i < len(foundResults)-1 {
			fmt.Printf("\n")
		}
	}
}
