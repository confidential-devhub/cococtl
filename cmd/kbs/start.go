package kbs

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"

	"github.com/spf13/cobra"

	"github.com/confidential-devhub/cococtl/pkg/config"
	"github.com/confidential-devhub/cococtl/pkg/k8s"
	"github.com/confidential-devhub/cococtl/pkg/trustee"
)

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Deploy or configure a KBS instance",
	Long: `Deploy or configure a Key Broker Service (KBS) instance.

--mode k8s  Deploy KBS to a Kubernetes cluster using the all-in-one Trustee image.
            The admin private key is written to --auth-dir (default: ~/.kube/coco-kbs-auth).
            Use 'kubectl coco kbs populate' afterwards to upload resources.

Example:
  kubectl coco kbs start --mode k8s --namespace coco-system
  kubectl coco kbs start --mode k8s --namespace coco-system --image ghcr.io/confidential-containers/key-broker-service:v0.17.0`,
	RunE: runStart,
}

var (
	startMode            string
	startResourceBackend string
	startNamespace       string
	startImage           string
	startAuthDir         string
)

func init() {
	startCmd.Flags().StringVar(&startMode, "mode", "k8s", "KBS deployment mode: k8s")
	startCmd.Flags().StringVar(&startResourceBackend, "resource-backend", "file", "Resource backend: file (default), vault (not yet implemented)")
	startCmd.Flags().StringVar(&startNamespace, "namespace", "", "Kubernetes namespace for KBS deployment (default: current context namespace)")
	startCmd.Flags().StringVar(&startImage, "image", "", "KBS container image (default: from config or built-in)")
	startCmd.Flags().StringVar(&startAuthDir, "auth-dir", "", "Directory to store the KBS admin private key (default: ~/.kube/coco-kbs-auth)")
}

func runStart(cmd *cobra.Command, _ []string) error {
	switch startMode {
	case "k8s":
		return runStartK8s(cmd)
	default:
		return fmt.Errorf("unknown --mode %q: supported values are: k8s", startMode)
	}
}

// checkKubectl returns a helpful error if kubectl is not found in PATH.
// trustee.Deploy shells out to kubectl; this surfaces a clear message rather
// than a raw exec error when kubectl is absent.
func checkKubectl() error {
	_, err := exec.LookPath("kubectl")
	if err != nil {
		return fmt.Errorf("kubectl is required for kbs start\n\n" +
			"To fix:\n" +
			"  1. Install kubectl: https://kubernetes.io/docs/tasks/tools/\n" +
			"  2. Ensure kubectl is in your PATH\n" +
			"  3. Verify with: kubectl version --client")
	}
	return nil
}

func runStartK8s(cmd *cobra.Command) error {
	if startResourceBackend == "vault" {
		return fmt.Errorf("--resource-backend vault is not yet implemented")
	}
	if startResourceBackend != "file" {
		return fmt.Errorf("unknown --resource-backend %q: supported values are: file, vault", startResourceBackend)
	}

	if err := checkKubectl(); err != nil {
		return err
	}

	// Resolve namespace
	namespace := startNamespace
	if namespace == "" {
		var err error
		namespace, err = k8s.GetCurrentNamespace()
		if err != nil {
			return fmt.Errorf("failed to get current namespace: %w", err)
		}
	}

	// Create K8s client
	k8sClient, err := k8s.NewClient(k8s.ClientOptions{})
	if err != nil {
		return fmt.Errorf("failed to create Kubernetes client: %w", err)
	}

	ctx := cmd.Context()

	// Load config for defaults. A missing file is non-fatal (errConfigNotFound).
	// Parse or permission errors are logged as warnings but do not abort.
	cfg, configErr := loadCocoConfig()
	if configErr != nil && !errors.Is(configErr, errConfigNotFound) {
		fmt.Fprintf(os.Stderr, "Warning: failed to load config file: %v\n", configErr)
	}

	// Determine KBS image
	image := startImage
	if image == "" {
		if cfg != nil && cfg.KBSImage != "" {
			image = cfg.KBSImage
		} else {
			image = config.DefaultKBSImage
		}
	}

	// Determine auth dir
	authDir := startAuthDir
	if authDir == "" && cfg != nil {
		authDir = cfg.KBSAuthDir
	}

	// Determine PCCS URL
	var pccsURL string
	if cfg != nil {
		pccsURL = cfg.PCCSURL
	}

	// Check if already deployed
	deployed, err := trustee.IsDeployed(ctx, k8sClient.Clientset, namespace)
	if err != nil {
		return fmt.Errorf("failed to check KBS deployment status: %w", err)
	}
	if deployed {
		kbsURL := trustee.GetServiceURL(namespace, "trustee-kbs")
		fmt.Printf("KBS is already deployed in namespace '%s'\n", namespace)
		fmt.Printf("KBS URL: %s\n", kbsURL)
		// Persist so that subsequent 'kbs populate' calls can derive namespace/auth-dir
		// from config without explicit flags, even when no fresh deploy happened.
		persistStartConfig(cfg, configErr, kbsURL, authDir)
		return nil
	}

	fmt.Printf("Deploying KBS to namespace '%s'...\n", namespace)

	trusteeCfg := &trustee.Config{
		Namespace:   namespace,
		ServiceName: "trustee-kbs",
		KBSImage:    image,
		PCCSURL:     pccsURL,
		RESTConfig:  k8sClient.Config,
		AuthDir:     authDir,
	}

	if err := trustee.Deploy(ctx, k8sClient.Clientset, trusteeCfg); err != nil {
		return fmt.Errorf("failed to deploy KBS: %w", err)
	}

	kbsURL := trustee.GetServiceURL(namespace, "trustee-kbs")
	persistStartConfig(cfg, configErr, kbsURL, trusteeCfg.AuthDir)

	fmt.Printf("KBS deployed successfully\n")
	fmt.Printf("KBS URL: %s\n", kbsURL)
	fmt.Printf("Auth dir: %s\n", trusteeCfg.AuthDir)
	fmt.Println()
	fmt.Println("To upload resources to KBS:")
	fmt.Printf("  kubectl coco kbs populate -f <secrets.yaml>\n")

	return nil
}

// persistStartConfig writes the KBS URL and auth dir to the on-disk config so
// that subsequent 'kbs populate' calls can resolve namespace and auth without
// requiring explicit flags. Called on both fresh deploy and already-deployed paths.
func persistStartConfig(cfg *config.CocoConfig, configErr error, kbsURL, authDir string) {
	// Start from defaults when config is absent (errConfigNotFound) or unreadable.
	if cfg == nil || (configErr != nil && !errors.Is(configErr, errConfigNotFound)) {
		cfg = config.DefaultConfig()
	}
	cfg.TrusteeServer = kbsURL
	if authDir != "" {
		cfg.KBSAuthDir = authDir
	}
	configPath, pathErr := config.GetConfigPath()
	if pathErr != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to determine config path, config not saved: %v\n", pathErr)
	} else if saveErr := cfg.Save(configPath); saveErr != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to update config file: %v\n", saveErr)
	}
}

// errConfigNotFound is returned by loadCocoConfig when no config file exists yet.
// Callers treat this as non-fatal ("no config yet") and use defaults instead.
var errConfigNotFound = errors.New("config file not found")

// loadCocoConfig loads the CoCo config from the default path.
// Returns errConfigNotFound when the file does not exist (non-fatal: use defaults).
// Other errors (parse failures, permission issues) are returned as-is.
func loadCocoConfig() (*config.CocoConfig, error) {
	configPath, err := config.GetConfigPath()
	if err != nil {
		return nil, err
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, errConfigNotFound
		}
		return nil, err
	}
	return cfg, nil
}
