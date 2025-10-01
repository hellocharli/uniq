package cmd

import (
	"github.com/spf13/cobra"

	"github.com/charlielowe/uniq/pkg/generators"
)

var ed25519Cmd = &cobra.Command{
	Use:   "ed25519 <prefix>",
	Short: "Generate Ed25519 key with base64 fingerprint prefix",
	Long:  `Generate Ed25519 SSH key with the specified base64 fingerprint prefix (e.g., "deadbabe").`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		prefix := args[0]
		generator := generators.NewEd25519Generator()
		runGenerator(generator, prefix, numResults)
	},
}