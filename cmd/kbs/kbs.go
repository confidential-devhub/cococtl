// Package kbs provides the kbs subcommand group for cococtl.
package kbs

import "github.com/spf13/cobra"

// KbsCmd is the root command for KBS (Key Broker Service) operations.
var KbsCmd = &cobra.Command{
	Use:   "kbs",
	Short: "Manage the Key Broker Service (KBS)",
	Long: `Commands for deploying, configuring, and interacting with the Key Broker Service (KBS) / Trustee.

Available subcommands:
  start     Deploy or configure a KBS instance
  populate  Upload resources to a KBS instance`,
}

func init() {
	KbsCmd.AddCommand(startCmd)
	KbsCmd.AddCommand(populateCmd)
}
