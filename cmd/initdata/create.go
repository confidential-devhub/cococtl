package initdata

import (
	"fmt"
	"os"
	"path/filepath"

	pkginitdata "github.com/confidential-devhub/cococtl/pkg/initdata"
	"github.com/spf13/cobra"
)

var createCmd = &cobra.Command{
	Use:   "create",
	Short: "Generate initdata TOML from CoCo config and save to disk",
	Long: `Generate initdata TOML from coco-config.toml and save it to disk.

Examples:
  kubectl coco initdata create
  kubectl coco initdata create --cacert /path/to/ca.crt
  kubectl coco initdata create --capath /etc/ssl/certs --output /tmp/initdata.toml`,
	RunE: runCreate,
}

var (
	createConfigPath string
	createCACert     string
	createCAPath     string
	createOutput     string
)

func init() {
	createCmd.Flags().StringVar(&createConfigPath, "config", "", "Path to CoCo config file (default: ~/.kube/coco-config.toml)")
	createCmd.Flags().StringVar(&createCACert, "cacert", "", "Path to CA cert PEM file")
	createCmd.Flags().StringVar(&createCAPath, "capath", "", "Path to directory of CA cert PEM files")
	createCmd.Flags().StringVar(&createOutput, "output", "", "Output file for raw TOML (default: ~/.kube/coco-initdata.toml)")
	createCmd.MarkFlagsMutuallyExclusive("cacert", "capath")
}

func runCreate(_ *cobra.Command, _ []string) error {
	if createCACert != "" && createCAPath != "" {
		return fmt.Errorf("--cacert and --capath are mutually exclusive")
	}

	cfg, err := loadConfig(createConfigPath)
	if err != nil {
		return err
	}

	var certPEM string
	switch {
	case createCACert != "":
		certs, err := loadCerts(createCACert)
		if err != nil {
			return err
		}
		if len(certs) == 0 {
			return fmt.Errorf("--cacert %s: no certificates found", createCACert)
		}
		if err := validateCerts(certs); err != nil {
			return err
		}
		certPEM = certsToPEM(certs)
	case createCAPath != "":
		certs, err := loadCertsFromDir(createCAPath)
		if err != nil {
			return err
		}
		if len(certs) == 0 {
			return fmt.Errorf("--capath %s: no certificates found", createCAPath)
		}
		if err := validateCerts(certs); err != nil {
			return err
		}
		certPEM = certsToPEM(certs)
	}

	raw, err := pkginitdata.GenerateRaw(cfg, certPEM, nil)
	if err != nil {
		return fmt.Errorf("failed to generate initdata: %w", err)
	}

	outputPath := createOutput
	if outputPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get home directory: %w", err)
		}
		outputPath = filepath.Join(home, ".kube", "coco-initdata.toml")
	}

	if err := os.MkdirAll(filepath.Dir(outputPath), 0750); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}
	if err := os.WriteFile(outputPath, raw, 0600); err != nil {
		return fmt.Errorf("failed to write initdata: %w", err)
	}

	fmt.Printf("Initdata written to %s\n", outputPath)
	return nil
}
