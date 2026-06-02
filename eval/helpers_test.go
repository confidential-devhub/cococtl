package eval_test

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

var (
	mu     sync.Mutex
	scores []scoreEntry
)

type scoreEntry struct {
	tier    string
	name    string
	passed  bool
	skipped bool
}

func TestMain(m *testing.M) {
	code := m.Run()
	printScorecard()
	os.Exit(code)
}

// check runs fn as a named subtest and records the outcome for the scorecard.
// Skipped subtests are tracked separately so they don't inflate the pass count.
func check(t *testing.T, tier, name string, fn func(*testing.T)) {
	t.Helper()
	var skipped bool
	passed := t.Run(name, func(t *testing.T) {
		t.Cleanup(func() { skipped = t.Skipped() })
		fn(t)
	})
	mu.Lock()
	scores = append(scores, scoreEntry{
		tier:    tier,
		name:    name,
		passed:  passed && !skipped,
		skipped: skipped,
	})
	mu.Unlock()
}

func printScorecard() {
	if len(scores) == 0 {
		return
	}
	var t1p, t1n, t1s, t2p, t2n, t2s int
	var failures []string
	for _, e := range scores {
		switch e.tier {
		case "offline":
			t1n++
			switch {
			case e.skipped:
				t1s++
			case e.passed:
				t1p++
			default:
				failures = append(failures, "offline/"+e.name)
			}
		case "cluster":
			t2n++
			switch {
			case e.skipped:
				t2s++
			case e.passed:
				t2p++
			default:
				failures = append(failures, "cluster/"+e.name)
			}
		}
	}
	skippedSuffix := func(n int) string {
		if n == 0 {
			return ""
		}
		return fmt.Sprintf("  (%d skipped)", n)
	}
	fmt.Printf("\nEVAL SCORECARD\n==============\n")
	fmt.Printf("Tier 1 (offline): %d/%d%s\n", t1p, t1n-t1s, skippedSuffix(t1s))
	if t2n > 0 {
		fmt.Printf("Tier 2 (cluster): %d/%d%s\n", t2p, t2n-t2s, skippedSuffix(t2s))
	}
	fmt.Printf("─────────────────────────\n")
	fmt.Printf("Overall:          %d/%d%s\n", t1p+t2p, t1n+t2n-t1s-t2s, skippedSuffix(t1s+t2s))
	if len(failures) > 0 {
		fmt.Println("\nFAILURES:")
		for _, f := range failures {
			fmt.Println(" -", f)
		}
	}
}

// binary returns the path to the kubectl-coco binary.
func binary(t *testing.T) string {
	t.Helper()
	if b := os.Getenv("COCOCTL_BINARY"); b != "" {
		return b
	}
	bin, err := filepath.Abs("../kubectl-coco")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(bin); err != nil {
		t.Fatalf("binary not found at %s — run `make build` first or set COCOCTL_BINARY", bin)
	}
	return bin
}

// fixtures returns the path to integration_test/testdata.
func fixtures(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs("../integration_test/testdata")
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

// minimalConfig writes a minimal coco config to dir and returns its path.
func minimalConfig(t *testing.T, dir string) string {
	t.Helper()
	const cfg = "trustee_server = 'https://kbs.example.com'\nruntime_class = 'kata-cc'\n"
	p := filepath.Join(dir, "coco-config.toml")
	if err := os.WriteFile(p, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// copyFixture copies src into dir and returns the new path.
// Required because apply writes the -coco.yaml output to the same directory as the input.
func copyFixture(t *testing.T, src, dir string) string {
	t.Helper()
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, filepath.Base(src))
	if err := os.WriteFile(dst, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return dst
}

// cocoOutput returns the *-coco.yaml path that apply writes for the given input.
func cocoOutput(input string) string {
	ext := filepath.Ext(input)
	base := strings.TrimSuffix(filepath.Base(input), ext)
	return filepath.Join(filepath.Dir(input), base+"-coco"+ext)
}

// runBin executes the cococtl binary and returns stdout, stderr, and exit code.
func runBin(t *testing.T, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()
	cmd := exec.Command(binary(t), args...)
	var outBuf, errBuf strings.Builder
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return outBuf.String(), errBuf.String(), ee.ExitCode()
		}
		return outBuf.String(), errBuf.String(), -1
	}
	return outBuf.String(), errBuf.String(), 0
}

// clusterAvailable returns true if kubectl can reach the API server.
func clusterAvailable() bool {
	return exec.Command("kubectl", "cluster-info").Run() == nil
}
