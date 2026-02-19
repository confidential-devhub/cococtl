// Package cmd provides the command-line interface for kubectl-coco.
package cmd

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/confidential-devhub/cococtl/pkg/config"
	"github.com/confidential-devhub/cococtl/pkg/initdata"
	"github.com/pelletier/go-toml/v2"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
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

Use --yaml -o FILE to write a reference YAML file containing the initdata TOML
(readable), the PCR8 reference value for attestation, and the encoded annotation.

Examples:
  # Show decoded initdata from default config
  kubectl coco dump-initdata

  # Show decoded initdata from specific config file
  kubectl coco dump-initdata --config /path/to/coco-config.toml

  # Show raw base64-encoded annotation value
  kubectl coco dump-initdata --raw

  # Write initdata reference YAML (TOML + PCR8) to a file
  kubectl coco dump-initdata --yaml -o app-initdata.yaml`,
	RunE: runDumpInitdata,
}

var (
	dumpInitdataConfigPath string
	dumpInitdataRaw        bool
	dumpInitdataYAML       bool
	dumpInitdataOutput     string
)

func init() {
	rootCmd.AddCommand(dumpInitdataCmd)

	dumpInitdataCmd.Flags().StringVar(&dumpInitdataConfigPath, "config", "", "Path to CoCo config file (default: ~/.kube/coco-config.toml)")
	dumpInitdataCmd.Flags().BoolVar(&dumpInitdataRaw, "raw", false, "Output gzip+base64 encoded annotation value instead of decoded content")
	dumpInitdataCmd.Flags().BoolVar(&dumpInitdataYAML, "yaml", false, "Write initdata reference YAML (readable TOML + PCR8) to file (use with -o)")
	dumpInitdataCmd.Flags().StringVarP(&dumpInitdataOutput, "output", "o", "", "Output file for --yaml")
}

// initdataReferenceYAML is the structure written for --yaml -o (metadata + initdata TOML + PCR8).
type initdataReferenceYAML struct {
	Metadata struct {
		Description string `yaml:"description"`
		Algorithm   string `yaml:"algorithm"`
	} `yaml:"metadata"`
	PCR8Reference string `yaml:"pcr8_reference"`
	InitdataTOML  string `yaml:"initdata_toml"`
	Encoded       string `yaml:"encoded,omitempty"`
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

	if cfg.TrusteeServer == "" {
		return fmt.Errorf("trustee_server is empty, initdata cannot be generated")
	}

	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	// --yaml -o: write reference YAML (raw TOML + PCR8 + encoded)
	if dumpInitdataYAML {
		if dumpInitdataOutput == "" {
			return fmt.Errorf("--yaml requires -o/--output (e.g. -o app-initdata.yaml)")
		}
		encoded, rawTOML, pcr8Hex, err := initdata.GenerateWithArtifacts(cfg, nil, cfg.TrusteeServer)
		if err != nil {
			return fmt.Errorf("failed to generate initdata: %w", err)
		}
		ref := initdataReferenceYAML{}
		ref.Metadata.Description = "Initdata TOML (before gzip+base64) and PCR8 reference for cc_init_data attestation. PCR8 = SHA256(initial_pcr_32zeros || SHA256(initdata_toml))."
		ref.Metadata.Algorithm = initdata.InitDataAlgorithm
		ref.PCR8Reference = pcr8Hex
		ref.InitdataTOML = rawTOML
		ref.Encoded = encoded
		out, err := yaml.Marshal(&ref)
		if err != nil {
			return fmt.Errorf("failed to marshal YAML: %w", err)
		}
		header := "# Initdata reference: readable TOML + PCR8 for attestation.\n" +
			"# Generate with: kubectl coco dump-initdata --yaml -o <file>\n"
		if err := os.WriteFile(dumpInitdataOutput, append([]byte(header), out...), 0600); err != nil {
			return fmt.Errorf("failed to write %s: %w", dumpInitdataOutput, err)
		}
		fmt.Printf("Wrote initdata reference to %s (initdata_toml, pcr8_reference, encoded)\n", dumpInitdataOutput)
		return nil
	}

	// Generate initdata (nil for imagePullSecrets - not needed for inspection)
	encoded, err := initdata.Generate(cfg, nil, cfg.TrusteeServer)
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
