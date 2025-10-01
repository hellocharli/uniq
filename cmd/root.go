package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var numResults int

var rootCmd = &cobra.Command{
	Use:   "uniq",
	Short: "Generate vanity cryptographic keys and hashes",
	Long:  `A unified tool for generating vanity cryptographic keys and hashes by brute-force.`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	// Global flag that works with any subcommand
	rootCmd.PersistentFlags().IntVarP(&numResults, "number", "n", 1, "number of results to generate")

	rootCmd.AddCommand(ntlmCmd)
	rootCmd.AddCommand(ed25519Cmd)
}