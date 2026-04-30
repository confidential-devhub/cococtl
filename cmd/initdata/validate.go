package initdata

import "github.com/spf13/cobra"

var validateCmd = &cobra.Command{Use: "validate", Short: "stub", RunE: func(*cobra.Command, []string) error { return nil }}
