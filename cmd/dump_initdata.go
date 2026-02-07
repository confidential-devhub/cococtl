// Package cmd provides the command-line interface for kubectl-coco.
package cmd

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"io"
	"strings"

	"github.com/confidential-devhub/cococtl/pkg/config"
	"github.com/confidential-devhub/cococtl/pkg/initdata"
	"github.com/pelletier/go-toml/v2"
	"github.com/spf13/cobra"
)

// dumpInitdataCmd displays generated initdata for inspection and debugging.
var dumpInitdataCmd = &cobra.Command{
	Use:   "dump-initdata",
	Short: "Display generated initdata for inspection",
	Long: `Display the generated initdata configuration for inspection and debugging.

By default, this command shows the decoded contents of:
  - aa.toml (Attestation Agent configuration)
  - cdh.toml (Confidential Data Hub configuration)
  - policy.rego (Kata agent policy)

Use --raw to output the gzip+base64 encoded annotation value that would
be added to Kubernetes manifests.

Examples:
  # Show decoded initdata from default config
  kubectl coco dump-initdata

  # Show decoded initdata from specific config file
  kubectl coco dump-initdata --config /path/to/coco-config.toml

  # Show raw base64-encoded annotation value
  kubectl coco dump-initdata --raw`,
	RunE: runDumpInitdata,
}

var (
	dumpInitdataConfigPath string
	dumpInitdataRaw        bool
)

func init() {
	rootCmd.AddCommand(dumpInitdataCmd)

	dumpInitdataCmd.Flags().StringVar(&dumpInitdataConfigPath, "config", "", "Path to CoCo config file (default: ~/.kube/coco-config.toml)")
	dumpInitdataCmd.Flags().BoolVar(&dumpInitdataRaw, "raw", false, "Output gzip+base64 encoded annotation value instead of decoded content")
}

// runDumpInitdata generates and displays initdata for inspection.
func runDumpInitdata(_ *cobra.Command, _ []string) error {
	// Determine config path
	configPath := dumpInitdataConfigPath
	if configPath == "" {
		var err error
		configPath, err = config.GetConfigPath()
		if err != nil {
			return fmt.Errorf("failed to get default config path: %w", err)
		}
	}

	// Load configuration
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config from %s: %w", configPath, err)
	}

	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	// Generate initdata (nil for imagePullSecrets - not needed for inspection)
	encoded, err := initdata.Generate(cfg, nil)
	if err != nil {
		return fmt.Errorf("failed to generate initdata: %w", err)
	}

	// Output based on --raw flag
	if dumpInitdataRaw {
		// Output raw base64-encoded value
		fmt.Println("# This is the gzip+base64 encoded initdata annotation value")
		fmt.Println("# Use this value for the io.katacontainers.config.hypervisor.cc_init_data annotation")
		fmt.Println(encoded)
		return nil
	}

	// Decode and display human-readable content
	decoded, err := decodeInitdata(encoded)
	if err != nil {
		return fmt.Errorf("failed to decode initdata: %w", err)
	}

	// Print each section with headers
	fmt.Println("=== aa.toml ===")
	if aaToml, ok := decoded["aa.toml"]; ok {
		fmt.Println(strings.TrimSpace(aaToml))
	} else {
		fmt.Println("(not found)")
	}
	fmt.Println()

	fmt.Println("=== cdh.toml ===")
	if cdhToml, ok := decoded["cdh.toml"]; ok {
		fmt.Println(strings.TrimSpace(cdhToml))
	} else {
		fmt.Println("(not found)")
	}
	fmt.Println()

	fmt.Println("=== policy.rego ===")
	if policy, ok := decoded["policy.rego"]; ok {
		fmt.Println(strings.TrimSpace(policy))
	} else {
		fmt.Println("(not found)")
	}

	return nil
}

// decodeInitdata decodes a base64+gzip encoded initdata string and extracts the data map.
func decodeInitdata(encoded string) (map[string]string, error) {
	// Decode base64
	gzipData, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64: %w", err)
	}

	// Decompress gzip
	gzipReader, err := gzip.NewReader(bytes.NewReader(gzipData))
	if err != nil {
		return nil, fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer func() {
		_ = gzipReader.Close()
	}()

	tomlData, err := io.ReadAll(gzipReader)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress gzip data: %w", err)
	}

	// Parse TOML to extract data map
	var initdataStruct initdata.InitData

	if err := toml.Unmarshal(tomlData, &initdataStruct); err != nil {
		return nil, fmt.Errorf("failed to parse initdata TOML: %w", err)
	}

	return initdataStruct.Data, nil
}
