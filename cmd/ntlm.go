package cmd

import (
	"strings"

	"github.com/spf13/cobra"

	"github.com/charlielowe/uniq/pkg/generators"
)

var ntlmCmd = &cobra.Command{
	Use:   "ntlm <prefix>",
	Short: "Generate NTLM hash with hex prefix",
	Long:  `Generate NTLM hash with the specified hex prefix (e.g., "ABC123").`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		prefix := strings.ToUpper(args[0])
		generator := generators.NewNTLMGenerator()
		runGenerator(generator, prefix, numResults)
	},
}