package initdata

import (
	"fmt"
	"os"
	"strings"

	pkginitdata "github.com/confidential-devhub/cococtl/pkg/initdata"
	"github.com/pelletier/go-toml/v2"
	"github.com/spf13/cobra"
)

var validateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate initdata structure and embedded certificates",
	Long: `Validate an initdata for structural correctness and certificate validity.

Reads from --file (plaintext TOML) or stdin (base64+gzip encoded blob).

Checks:
  - TOML parses cleanly
  - version == "0.1.0" and algorithm == "sha256"
  - aa.toml, cdh.toml, policy.rego are present
  - Embedded CA certs in aa.toml / cdh.toml pass validation

Examples:
  kubectl coco initdata validate --file ~/.kube/coco-initdata.toml
  kubectl coco initdata dump | kubectl coco initdata validate`,
	RunE: runValidate,
}

var validateFile string

func init() {
	validateCmd.Flags().StringVar(&validateFile, "file", "", "Path to plaintext initdata TOML file (reads encoded blob from stdin if not set)")
}

func runValidate(_ *cobra.Command, _ []string) error {
	tomlBytes, err := loadInitdataTOML(validateFile, os.Stdin)
	if err != nil {
		return fmt.Errorf("failed to load initdata: %w", err)
	}

	var id pkginitdata.InitData
	if err := toml.Unmarshal(tomlBytes, &id); err != nil {
		return fmt.Errorf("failed to parse TOML: %w", err)
	}

	var failures []string

	if id.Version != pkginitdata.InitDataVersion {
		failures = append(failures, fmt.Sprintf("version: got %q, want %q", id.Version, pkginitdata.InitDataVersion))
	}
	if id.Algorithm != pkginitdata.InitDataAlgorithm {
		failures = append(failures, fmt.Sprintf("algorithm: got %q, want %q", id.Algorithm, pkginitdata.InitDataAlgorithm))
	}
	for _, key := range []string{"aa.toml", "cdh.toml", "policy.rego"} {
		if _, ok := id.Data[key]; !ok {
			failures = append(failures, fmt.Sprintf("missing required data key: %s", key))
		}
	}

	certs, err := extractCertsFromInitdata(id.Data)
	if err != nil {
		failures = append(failures, fmt.Sprintf("cert extraction failed: %v", err))
	} else if len(certs) > 0 {
		if err := validateCerts(certs); err != nil {
			failures = append(failures, err.Error())
		}
	}

	if len(failures) > 0 {
		return fmt.Errorf("validation failed:\n  %s", strings.Join(failures, "\n  "))
	}

	fmt.Println("Validation passed.")
	return nil
}
