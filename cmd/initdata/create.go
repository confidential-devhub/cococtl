package initdata

import "github.com/spf13/cobra"

var createCmd = &cobra.Command{Use: "create", Short: "stub", RunE: func(*cobra.Command, []string) error { return nil }}
