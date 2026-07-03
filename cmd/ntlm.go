package cmd

import (
	"fmt"
	"os"
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
		if !forceCPU {
			if g, err := generators.NewMetalNTLMGenerator(); err == nil {
				defer g.Close()
				runGenerator(g, prefix, numResults)
				return
			} else {
				fmt.Fprintf(os.Stderr, "GPU unavailable (%v); using CPU\n", err)
			}
		}
		runGenerator(generators.NewNTLMGenerator(), prefix, numResults)
	},
}
