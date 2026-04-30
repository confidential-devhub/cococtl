package initdata

import "github.com/spf13/cobra"

// InitdataCmd is the root command for initdata operations.
var InitdataCmd = &cobra.Command{
	Use:   "initdata",
	Short: "Manage initdata for Confidential Containers",
	Long: `Commands for creating, inspecting, and validating initdata.

Available subcommands:
  create    Generate initdata TOML from CoCo config and save to disk
  dump      Display initdata as base64+gzip blob or plaintext TOML
  validate  Validate initdata structure and embedded certificates`,
}

func init() {
	InitdataCmd.AddCommand(createCmd)
	InitdataCmd.AddCommand(dumpCmd)
	InitdataCmd.AddCommand(validateCmd)
}
