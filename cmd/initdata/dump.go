package initdata

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

var dumpCmd = &cobra.Command{
	Use:   "dump",
	Short: "Display initdata from saved TOML file",
	Long: `Display initdata from the saved raw TOML file.

Default output is the base64+gzip encoded blob ready for use as the
io.katacontainers.config.hypervisor.cc_init_data annotation.

Use --raw to output the plaintext TOML instead.

Examples:
  kubectl coco initdata dump
  kubectl coco initdata dump --raw
  kubectl coco initdata dump --file /path/to/initdata.toml`,
	RunE: runDump,
}

var (
	dumpFile string
	dumpRaw  bool
)

func init() {
	dumpCmd.Flags().StringVar(&dumpFile, "file", "", "Path to raw initdata TOML file (default: ~/.kube/coco-initdata.toml)")
	dumpCmd.Flags().BoolVar(&dumpRaw, "raw", false, "Output plaintext TOML instead of encoded blob")
}

func runDump(_ *cobra.Command, _ []string) error {
	filePath := dumpFile
	if filePath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get home directory: %w", err)
		}
		filePath = filepath.Join(home, ".kube", "coco-initdata.toml")
	}

	// #nosec G304 -- path comes from --file flag or defaults to ~/.kube/coco-initdata.toml
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", filePath, err)
	}

	if dumpRaw {
		_, err = os.Stdout.Write(data)
		return err
	}

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(data); err != nil {
		return fmt.Errorf("failed to compress: %w", err)
	}
	if err := gz.Close(); err != nil {
		return fmt.Errorf("failed to close gzip writer: %w", err)
	}
	fmt.Println(base64.StdEncoding.EncodeToString(buf.Bytes()))
	return nil
}
