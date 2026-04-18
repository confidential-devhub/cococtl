package kbs

import (
	"errors"
	"fmt"
	"io/fs"
	"net/url"
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

--mode k8s       Deploy KBS to a Kubernetes cluster using the all-in-one Trustee image.
                 The admin private key is written to --auth-dir (default: ~/.kube/coco-kbs-auth).
                 Use 'kubectl coco kbs populate' afterwards to upload resources.

--mode external  Register a pre-existing KBS instance. Writes --url and --auth-dir to
                 config so 'kbs populate' can connect without explicit flags.
                 No Kubernetes interaction occurs.

Examples:
  kubectl coco kbs start --mode k8s --namespace coco-system
  kubectl coco kbs start --mode external --url http://kbs.example.com:8080
  kubectl coco kbs start --mode external --url http://kbs.example.com:8080 --auth-dir ~/.kube/my-kbs-auth`,
	RunE: runStart,
}

var (
	startMode            string
	startResourceBackend string
	startNamespace       string
	startImage           string
	startAuthDir         string
	startURL             string
)

func init() {
	startCmd.Flags().StringVar(&startMode, "mode", "k8s", "KBS deployment mode: k8s, external")
	startCmd.Flags().StringVar(&startResourceBackend, "resource-backend", "file", "Resource backend: file (default), vault (not yet implemented)")
	startCmd.Flags().StringVar(&startNamespace, "namespace", "", "Kubernetes namespace for KBS deployment (default: current context namespace)")
	startCmd.Flags().StringVar(&startImage, "image", "", "KBS container image (default: from config or built-in)")
	startCmd.Flags().StringVar(&startAuthDir, "auth-dir", "", "Directory to store the KBS admin private key (default: ~/.kube/coco-kbs-auth)")
	startCmd.Flags().StringVar(&startURL, "url", "", "URL of the external KBS instance (required for --mode external)")
}

func runStart(cmd *cobra.Command, _ []string) error {
	switch startMode {
	case "k8s":
		return runStartK8s(cmd)
	case "external":
		return runStartExternal(cmd)
	default:
		return fmt.Errorf("unknown --mode %q: supported values are: k8s, external", startMode)
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
		if err := persistStartConfig(cfg, kbsURL, authDir); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: %v\n", err)
		}
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
	if err := persistStartConfig(cfg, kbsURL, trusteeCfg.AuthDir); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: %v\n", err)
	}

	fmt.Printf("KBS deployed successfully\n")
	fmt.Printf("KBS URL: %s\n", kbsURL)
	fmt.Printf("Auth dir: %s\n", trusteeCfg.AuthDir)
	fmt.Println()
	fmt.Println("To upload resources to KBS:")
	fmt.Printf("  kubectl coco kbs populate -f <secrets.yaml>\n")

	return nil
}

func persistStartConfig(cfg *config.CocoConfig, kbsURL, authDir string) error {
	if cfg == nil {
		cfg = config.DefaultConfig()
	}
	cfg.TrusteeServer = kbsURL
	if authDir != "" {
		cfg.KBSAuthDir = authDir
	}
	configPath, err := config.GetConfigPath()
	if err != nil {
		return fmt.Errorf("failed to determine config path: %w", err)
	}
	if err := cfg.Save(configPath); err != nil {
		return fmt.Errorf("failed to save config to %q: %w", configPath, err)
	}
	return nil
}

func runStartExternal(_ *cobra.Command) error {
	if startURL == "" {
		return fmt.Errorf("--url is required for --mode external")
	}

	u, err := url.Parse(startURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return fmt.Errorf("--url must be a valid http:// or https:// URL with a host, got %q", startURL)
	}
	if (u.Path != "" && u.Path != "/") || u.RawPath != "" {
		return fmt.Errorf("--url must be a base URL of the form http://host[:port] or https://host[:port], without a path, got %q", startURL)
	}
	if u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return fmt.Errorf("--url must not include query, fragment, or userinfo components, got %q", startURL)
	}

	cfg, configErr := loadCocoConfig()
	if configErr != nil && !errors.Is(configErr, errConfigNotFound) {
		fmt.Fprintf(os.Stderr, "Warning: failed to load config file: %v\n", configErr)
	}

	if err := persistStartConfig(cfg, startURL, startAuthDir); err != nil {
		return err
	}

	fmt.Printf("External KBS configured\n")
	fmt.Printf("KBS URL: %s\n", startURL)
	if startAuthDir != "" {
		fmt.Printf("Auth dir: %s\n", startAuthDir)
	}
	fmt.Println()
	fmt.Println("To upload resources to KBS:")
	fmt.Println("  kubectl coco kbs populate -f <secrets.yaml>")

	return nil
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
