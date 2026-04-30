package initdata

import "github.com/spf13/cobra"

var dumpCmd = &cobra.Command{Use: "dump", Short: "stub", RunE: func(*cobra.Command, []string) error { return nil }}
